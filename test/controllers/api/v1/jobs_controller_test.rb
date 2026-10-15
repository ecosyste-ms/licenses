require 'test_helper'

class ApiV1JobsControllerTest < ActionDispatch::IntegrationTest
  test 'submit a job' do
    post api_v1_jobs_path(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')
    assert_response :redirect
    assert_match /\/api\/v1\/jobs\//, @response.location
  end

  test 'submit an invalid job' do
    post api_v1_jobs_path
    assert_response :bad_request

    actual_response = JSON.parse(@response.body)

    assert_equal actual_response["title"], "Bad Request"
    assert_equal actual_response["details"], ["Url can't be blank"]
  end

  test 'check on a job' do
    @job = Job.create(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')

    @job.expects(:check_status)
    Job.expects(:find).with(@job.id).returns(@job)

    get api_v1_job_path(id: @job.id)
    assert_response :success
    assert_template 'jobs/show', file: 'jobs/show.json.jbuilder'
    
    actual_response = JSON.parse(@response.body)

    assert_equal actual_response["url"], @job.url
  end

  test 'completed jobs keep the v1 licenses and matched_files results' do
    job = Job.create(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')
    job.stubs(:resolve_addresses).returns(['93.184.216.34'])
    job.stubs(:licenses_as_json).returns(
      'schema' => 2,
      'expressions' => [{ 'expression' => 'AGPL-3.0-only', 'identification' => 'identified', 'root' => true }],
      'files' => [{ 'path' => 'LICENSE', 'roles' => ['license'], 'license_text_coverage' => 100.0, 'detections' => [] }],
      'declared' => []
    )
    stub_request(:get, job.url).to_return(status: 200, body: file_fixture('main.zip'))
    job.perform_license_parsing

    get api_v1_job_path(id: job.id)
    assert_response :success

    results = JSON.parse(@response.body)['results']
    assert_equal ['licenses', 'matched_files'], results.keys.sort
    assert_equal 'agpl-3.0-only', results.dig('licenses', 0, 'key')
    assert_equal 'AGPL-3.0-only', results.dig('licenses', 0, 'name')
    assert_equal 'LICENSE', results.dig('matched_files', 0, 'filename')
    assert_equal 100.0, results.dig('matched_files', 0, 'confidence')
    assert_match 'GNU AFFERO GENERAL PUBLIC LICENSE', results.dig('matched_files', 0, 'content')
  end

  test 'completed jobs only report root package licenses' do
    job = Job.create(url: 'https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip')
    job.stubs(:resolve_addresses).returns(['93.184.216.34'])
    job.stubs(:licenses_as_json).returns(
      'schema' => 2,
      'expressions' => [
        { 'expression' => 'AGPL-3.0-only', 'identification' => 'identified', 'root' => true },
        { 'expression' => 'Apache-2.0', 'identification' => 'identified', 'root' => false },
        { 'expression' => 'MIT', 'identification' => 'identified', 'root' => false }
      ],
      'files' => [
        { 'path' => 'LICENSE', 'roles' => ['license'], 'license_text_coverage' => 100.0,
          'detections' => [{ 'expression' => 'AGPL-3.0-only', 'identification' => 'identified',
                             'matches' => [{ 'license_ids' => ['AGPL-3.0-only'], 'score' => 100.0 }] }] },
        { 'path' => 'src/other.rb', 'roles' => [], 'license_text_coverage' => 0.0,
          'detections' => [{ 'expression' => 'Apache-2.0', 'identification' => 'identified',
                             'matches' => [{ 'license_ids' => ['Apache-2.0'], 'score' => 100.0 }] }] },
        { 'path' => 'vendor/lib/LICENSE', 'roles' => ['license'], 'license_text_coverage' => 100.0,
          'detections' => [{ 'expression' => 'MIT', 'identification' => 'identified',
                             'matches' => [{ 'license_ids' => ['MIT'], 'score' => 100.0 }] }] }
      ],
      'declared' => [
        { 'path' => 'package.json', 'normalized_expression' => 'AGPL-3.0-only' },
        { 'path' => 'vendor/lib/package.json', 'normalized_expression' => 'BSD-3-Clause' }
      ]
    )
    stub_request(:get, job.url).to_return(status: 200, body: file_fixture('main.zip'))
    job.perform_license_parsing

    get api_v1_job_path(id: job.id)
    assert_response :success

    results = JSON.parse(@response.body)['results']
    assert_equal ['agpl-3.0-only'], results['licenses'].map { |license| license['key'] }
    assert_equal ['LICENSE'], results['matched_files'].map { |file| file['filename'] }
  end

  test 'completed jobs keep the root license text when nested license files exceed the attribution budget' do
    url = 'https://example.com/package.tgz'
    nested_paths = Array.new(105) { |index| "Godeps/d#{index}/LICENSE" }
    body = Dir.mktmpdir do |dir|
      source = File.join(dir, 'package')
      (nested_paths + ['LICENSE']).each do |path|
        file = File.join(source, path)
        FileUtils.mkdir_p(File.dirname(file))
        File.write(file, path == 'LICENSE' ? 'MIT License root text' : 'Apache License nested text')
      end
      archive = File.join(dir, 'package.tgz')
      assert system('bsdtar', '-czf', archive, '-C', dir, 'package')
      File.binread(archive)
    end

    # The scanner sorts files by path, so uppercase vendored directories precede the root LICENSE.
    files = (nested_paths + ['LICENSE']).sort.map do |path|
      { 'path' => path, 'roles' => ['license'], 'license_text_coverage' => 100.0, 'detections' => [] }
    end
    assert_operator Job::MAX_ATTRIBUTION_FILES, :<, files.index { |file| file['path'] == 'LICENSE' }

    job = Job.create(url: url)
    job.stubs(:resolve_addresses).returns(['93.184.216.34'])
    job.stubs(:licenses_as_json).returns(
      'schema' => 2,
      'expressions' => [{ 'expression' => 'MIT', 'identification' => 'identified', 'root' => true }],
      'files' => files,
      'declared' => []
    )
    stub_request(:get, url).to_return(status: 200, body: body)
    job.perform_license_parsing

    get api_v1_job_path(id: job.id)
    assert_response :success

    results = JSON.parse(@response.body)['results']
    assert_equal ['mit'], results['licenses'].map { |license| license['key'] }
    assert_equal [{ 'filename' => 'LICENSE', 'confidence' => 100.0, 'content' => 'MIT License root text' }],
      results['matched_files']
  end
end
