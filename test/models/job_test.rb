require "test_helper"

class JobTest < ActiveSupport::TestCase
  context "validations" do
    should validate_presence_of(:url)
    should validate_uniqueness_of(:id).case_insensitive
  end

  setup do
    @job = Job.create(
      url: "https://github.com/ecosyste-ms/digest/archive/refs/heads/main.zip",
      sidekiq_id: "123",
      ip: "123.456.78.9"
    )
  end

  test "check_status" do
    Sidekiq::Status.expects(:status).with(@job.sidekiq_id).returns(:queued)
    @job.check_status
    assert_equal "queued", @job.status
  end

  test "parse_licenses_async" do
    ParseLicensesWorker.expects(:perform_async).with(@job.id)
    @job.parse_licenses_async
  end

  test "parse_licenses extracts a zip and scans the common wrapper directory" do
    @job.expects(:licenses_as_json).with do |destination|
      File.file?(File.join(destination, "LICENSE")) && File.basename(destination) == "digest-main"
    end.returns(scan_report)

    Dir.mktmpdir do |dir|
      FileUtils.cp(File.join(file_fixture_path, "main.zip"), dir)
      results = @job.parse_licenses(dir)

      assert_equal "agpl-3.0-only", results.dig(:licenses, 0, :key)
      assert_equal "LICENSE", results.dig(:matched_files, 0, :filename)
      assert_match "GNU AFFERO GENERAL PUBLIC LICENSE", results.dig(:matched_files, 0, :content)
    end
  end

  test "parse_licenses keeps the v1 licenses and matched_files contract" do
    Dir.mktmpdir do |root|
      File.write(File.join(root, "LICENSE"), "MIT License text")
      report = scan_report(expression: "MIT")
      report["files"][0]["detections"] = [detection("MIT", score: 98.5)]
      report["declared"] = [{ "path" => "package.json", "normalized_expression" => "MIT OR (Apache-2.0 WITH LLVM-exception)" }]
      @job.stubs(:scan_archive).returns(Job::Scan.new(report: report, root: root, skipped: []))

      results = @job.parse_licenses("/unused")

      assert_equal ["mit", "apache-2.0"], results[:licenses].map { |license| license[:key] }
      assert_equal(
        {
          key: "mit",
          name: "MIT",
          source: "MIT",
          description: "MIT",
          content: "MIT License text",
          permissions: "MIT",
          conditions: "MIT",
          limitations: "MIT"
        },
        results[:licenses].first
      )
      assert_equal [{ filename: "LICENSE", confidence: 98.5, content: "MIT License text" }], results[:matched_files]
    end
  end

  test "download_file streams the archive and calculates its checksum" do
    @job.stubs(:resolve_addresses).returns(["93.184.216.34"])
    stub_request(:get, @job.url).to_return(status: 200, body: file_fixture("main.zip"))

    Dir.mktmpdir do |dir|
      sha256 = @job.download_file(dir)
      assert_equal "546b13eb945186f67d2480910dce773ca0e2539b80cadafe7bb2fe3c537800ec", sha256
    end
  end

  test "download_file rejects archive filenames that could escape the temporary directory" do
    ["https://example.com", "https://example.com/", "https://example.com/.", "https://example.com/.."].each do |url|
      @job.url = url

      Dir.mktmpdir do |dir|
        assert_raises(Job::InvalidRequest) { @job.download_file(dir) }
      end
    end
  end

  test "download_file rejects addresses that are not globally routable" do
    @job.stubs(:resolve_addresses).returns(["127.0.0.1"])

    Dir.mktmpdir do |dir|
      error = assert_raises(Job::InvalidRequest) { @job.download_file(dir) }
      assert_equal "URL resolves to a blocked address", error.message
    end
  end

  test "download_file rechecks a redirect target" do
    @job.stubs(:resolve_addresses).with("github.com", 443).returns(["93.184.216.34"])
    @job.stubs(:resolve_addresses).with("169.254.169.254", 80).returns(["169.254.169.254"])
    stub_request(:get, @job.url).to_return(status: 302, headers: { "Location" => "http://169.254.169.254/latest" })

    Dir.mktmpdir do |dir|
      assert_raises(Job::InvalidRequest) { @job.download_file(dir) }
    end
  end

  test "download_file follows redirects after closing each request" do
    redirected_url = "https://downloads.example.com/main.zip"
    @job.stubs(:resolve_addresses).returns(["93.184.216.34"])
    stub_request(:get, @job.url).to_return(status: 302, headers: { "Location" => redirected_url })
    stub_request(:get, redirected_url).to_return(status: 200, body: "archive")

    Dir.mktmpdir do |dir|
      assert_equal Digest::SHA256.hexdigest("archive"), @job.download_file(dir)
    end

    assert_requested :get, @job.url, times: 1
    assert_requested :get, redirected_url, times: 1
  end

  test "perform_license_parsing stores the CLI report" do
    @job.stubs(:resolve_addresses).returns(["93.184.216.34"])
    @job.stubs(:licenses_as_json).returns(scan_report)
    stub_request(:get, @job.url).to_return(status: 200, body: file_fixture("main.zip"))

    @job.perform_license_parsing

    assert_equal "complete", @job.status, "expected complete, got #{@job.status}: #{@job.results.inspect}"
    assert_equal "546b13eb945186f67d2480910dce773ca0e2539b80cadafe7bb2fe3c537800ec", @job.sha256
    assert_equal ["licenses", "matched_files"], @job.results.keys.sort
    assert_equal "agpl-3.0-only", @job.results.dig("licenses", 0, "key")
    assert_equal "LICENSE", @job.results.dig("matched_files", 0, "filename")
  end

  test "perform_license_parsing records errors" do
    @job.stubs(:resolve_addresses).returns(["93.184.216.34"])
    stub_request(:get, @job.url).to_return(status: 404, body: "Not Found")

    @job.perform_license_parsing

    assert_equal "error", @job.status
    assert_predicate @job.results["error"], :present?
  end

  test "licenses_as_json accepts complete, incomplete, and no-detection reports" do
    [0, 2, 3].each do |exitstatus|
      status = stub(exitstatus: exitstatus)
      Open3.expects(:capture3)
        .with("licenses", "-json", "-max-files", "10000", "/scan")
        .returns([JSON.generate(scan_report), "", status])

      assert_equal 2, @job.licenses_as_json("/scan")["schema"]
    end
  end

  test "licenses_as_json treats exit status one as fatal" do
    status = stub(exitstatus: 1)
    Open3.expects(:capture3).returns(["", "matcher initialization failed", status])

    error = assert_raises(Job::ScannerError) { @job.licenses_as_json("/scan") }
    assert_equal "matcher initialization failed", error.message
  end

  test "scan_v2 adds archive metadata and complete attribution files" do
    Dir.mktmpdir do |root|
      contents = "Copyright Example\nLicense text\n"
      File.write(File.join(root, "LICENSE"), contents)
      report = scan_report
      report["files"][0]["sha256"] = Digest::SHA256.hexdigest(contents)

      @job.stubs(:download_file).returns("a" * 64)
      @job.stubs(:scan_archive).returns(Job::Scan.new(report: report, root: root, skipped: []))

      result = @job.scan_v2

      assert_equal @job.url, result["url"]
      assert_equal "a" * 64, result["sha256"]
      assert_equal contents, result.dig("attribution_files", 0, "content")
      assert_equal ["license"], result.dig("attribution_files", 0, "roles")
    end
  end

  test "scan_v2 limits attribution files by decoded UTF-8 size" do
    Dir.mktmpdir do |root|
      contents = "\xE9".b * ((Job::MAX_ATTRIBUTION_BYTES / 2) + 1)
      File.binwrite(File.join(root, "LICENSE"), contents)
      report = scan_report
      report["files"][0]["size"] = contents.bytesize
      report["files"][0]["sha256"] = Digest::SHA256.hexdigest(contents)
      report["files"][0]["encoding"] = "iso-8859-1"

      @job.stubs(:download_file).returns("a" * 64)
      @job.stubs(:scan_archive).returns(Job::Scan.new(report: report, root: root, skipped: []))

      result = @job.scan_v2

      assert_empty result["attribution_files"]
      assert_includes result["skipped"], { "path" => "LICENSE", "reason" => "attribution-limit" }
    end
  end

  test "works with gzip tarballs" do
    @job.url = "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"
    @job.expects(:licenses_as_json).with do |destination|
      File.file?(File.join(destination, "LICENSE")) && File.basename(destination) == "pkg"
    end.returns(scan_report(expression: "MIT"))

    Dir.mktmpdir do |dir|
      FileUtils.cp(File.join(file_fixture_path, "pkg-1.0.0.tgz"), dir)
      results = @job.parse_licenses(dir)
      assert_equal "mit", results.dig(:licenses, 0, :key)
    end
  end

  test "works with jar files that have no common wrapper" do
    @job.url = "https://repo.clojars.org/example.jar"
    @job.expects(:licenses_as_json).with do |destination|
      File.directory?(File.join(destination, "META-INF")) && File.basename(destination) == "archive"
    end.returns(scan_report(expression: nil, files: []))

    Dir.mktmpdir do |dir|
      FileUtils.cp(File.join(file_fixture_path, "clj-data-adapter-0.2.1.jar"), File.join(dir, "example.jar"))
      results = @job.parse_licenses(dir)
      assert_empty results[:licenses]
      assert_empty results[:matched_files]
    end
  end

  test "works with tar.xz archives" do
    @job.url = "https://example.com/package.tar.xz"

    Dir.mktmpdir do |dir|
      source = File.join(dir, "source", "package")
      FileUtils.mkdir_p(source)
      File.write(File.join(source, "LICENSE"), "license")
      archive = File.join(dir, "package.tar.xz")
      assert system("bsdtar", "-cJf", archive, "-C", File.dirname(source), "package")
      @job.expects(:licenses_as_json).with { |destination| File.file?(File.join(destination, "LICENSE")) }
        .returns(scan_report)

      assert_equal "agpl-3.0-only", @job.parse_licenses(dir).dig(:licenses, 0, :key)
    end
  end

  test "works with Ruby gem archives" do
    @job.url = "https://example.com/package.gem"

    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      FileUtils.mkdir_p(source)
      File.write(File.join(source, "LICENSE"), "license")
      payload = File.join(dir, "data.tar.gz")
      assert system("bsdtar", "-czf", payload, "-C", source, "LICENSE")
      archive = File.join(dir, "package.gem")
      assert system("bsdtar", "-cf", archive, "-C", dir, "data.tar.gz")
      @job.expects(:licenses_as_json).with { |destination| File.file?(File.join(destination, "LICENSE")) }
        .returns(scan_report)

      assert_equal "agpl-3.0-only", @job.parse_licenses(dir).dig(:licenses, 0, :key)
    end
  end

  test "rejects traversal archive paths" do
    error = assert_raises(Job::ExtractionError) { @job.send(:safe_archive_path, "../escape") }
    assert_match "traversal", error.message
  end

  test "skips symlinks and hard links during extraction" do
    @job.url = "https://example.com/links.tar"

    Dir.mktmpdir do |dir|
      source = File.join(dir, "source")
      FileUtils.mkdir_p(source)
      license = File.join(source, "LICENSE")
      File.write(license, "license")
      File.link(license, File.join(source, "HARDLINK"))
      File.symlink("LICENSE", File.join(source, "SYMLINK"))
      archive = File.join(dir, "links.tar")
      assert system("bsdtar", "-cf", archive, "-C", source, "LICENSE", "HARDLINK", "SYMLINK")
      @job.expects(:licenses_as_json).with do |destination|
        File.file?(File.join(destination, "LICENSE")) &&
          !File.exist?(File.join(destination, "HARDLINK")) &&
          !File.exist?(File.join(destination, "SYMLINK"))
      end.returns(scan_report)

      scan = @job.scan_archive(dir)
      skipped_paths = scan.skipped.map { |record| record["path"] }
      assert_equal ["HARDLINK", "SYMLINK"], skipped_paths
    end
  end

  test "extracts bracketed and glob-like filenames literally" do
    @job.url = "https://example.com/package.tgz"

    Dir.mktmpdir do |dir|
      names = ["LICENSE", "app/[slug]/page.tsx", "app/a*b?.txt", "app/[!x]"]
      build_archive(dir, "package.tgz", *names)
      @job.expects(:licenses_as_json).with do |destination|
        names.all? { |name| File.file?(File.join(destination, name)) }
      end.returns(scan_report)

      @job.scan_archive(dir)
    end
  end

  test "extracts non-ASCII and backslash filenames that bsdtar escapes in listings" do
    @job.url = "https://example.com/package.tgz"
    names = ["pkg/licen\u00E7a.txt", "pkg/back\\slash"]

    Dir.mktmpdir do |dir|
      build_archive(dir, "package.tgz", *names)
      @job.expects(:licenses_as_json).with do |destination|
        names.all? { |name| File.file?(File.join(File.dirname(destination), name)) }
      end.returns(scan_report)

      @job.scan_archive(dir)
    end
  end

  test "rejects archives with too many entries before reading the full listing" do
    @job.url = "https://example.com/package.tgz"

    Dir.mktmpdir do |dir|
      build_archive(dir, "package.tgz", *Array.new(50) { |index| "pkg/file#{index}" })
      parsed = 0
      parse = @job.method(:parse_archive_entry)
      @job.define_singleton_method(:parse_archive_entry) do |*arguments|
        parsed += 1
        parse.call(*arguments)
      end

      stub_const(Job, :MAX_ARCHIVE_ENTRIES, 5) do
        error = assert_raises(Job::LimitExceeded) { @job.scan_archive(dir) }
        assert_equal "archive contains more than 5 entries", error.message
      end
      assert_equal 5, parsed
    end
  end

  test "rejects archives whose paths exceed the byte limit before reading the full listing" do
    @job.url = "https://example.com/package.tgz"

    Dir.mktmpdir do |dir|
      build_archive(dir, "package.tgz", *Array.new(50) { |index| "pkg/file#{index}" })

      stub_const(Job, :MAX_ARCHIVE_PATH_BYTES, 40) do
        error = assert_raises(Job::LimitExceeded) { @job.scan_archive(dir) }
        assert_equal "archive paths exceed 40 bytes", error.message
      end
    end
  end

  test "kills archive commands that exceed the time limit" do
    stub_const(Job, :ARCHIVE_COMMAND_TIMEOUT, 0.2) do
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      error = assert_raises(Job::LimitExceeded) do
        @job.send(:run_archive_command, "sleep", "10") { |stdout| stdout.read }
      end

      assert_equal "archive processing exceeded 0.2 seconds", error.message
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 5
    end
  end

  private

  def build_archive(dir, archive_name, *paths)
    source = File.join(dir, "source")
    paths.each do |path|
      file = File.join(source, path)
      FileUtils.mkdir_p(File.dirname(file))
      File.write(file, "content")
    end
    archive = File.join(dir, archive_name)
    assert system("bsdtar", "-czf", archive, "-C", source, *Dir.children(source))
    archive
  end

  def detection(expression, score: 100.0)
    {
      "expression" => expression,
      "identification" => "identified",
      "matches" => [
        {
          "rule_id" => "#{expression.downcase}.LICENSE",
          "license_ids" => [expression],
          "kind" => "text",
          "method" => "exact",
          "score" => score,
          "coverage" => 100.0,
          "start" => 1,
          "end" => 1
        }
      ]
    }
  end

  def scan_report(expression: "AGPL-3.0-only", files: nil)
    report_files = files || [
      {
        "path" => "LICENSE",
        "size" => 34_523,
        "sha256" => "b" * 64,
        "encoding" => "utf-8",
        "roles" => ["license"],
        "license_text_coverage" => 100.0,
        "detections" => [],
        "clues" => []
      }
    ]
    expressions = expression ? [
      {
        "expression" => expression,
        "identification" => "identified",
        "root" => true,
        "files" => 1,
        "matches" => 1
      }
    ] : []

    {
      "schema" => 2,
      "root" => "/scan",
      "scope" => "project",
      "scanner" => { "name" => "git-pkgs/licenses", "version" => "0.5.0" },
      "corpus" => { "version" => "32.3.1", "rule_count" => 39_215, "source_commit" => "abc" },
      "summary" => { "truncated" => false },
      "declared" => [],
      "expressions" => expressions,
      "files" => report_files,
      "skipped" => [],
      "errors" => []
    }
  end
end
