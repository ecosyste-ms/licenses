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
end
