require "test_helper"

class ApiV2LicensesControllerTest < ActionDispatch::IntegrationTest
  test "returns the synchronous CLI report" do
    report = {
      "schema" => 2,
      "url" => "https://example.com/package.tar.gz",
      "sha256" => "a" * 64,
      "attribution_files" => []
    }
    Job.any_instance.stubs(:scan_v2).returns(report)

    get api_v2_licenses_path(url: report["url"])

    assert_response :success
    assert_equal report, response.parsed_body
    assert_match "public", response.headers["Cache-Control"]
  end

  test "requires a URL" do
    get api_v2_licenses_path

    assert_response :bad_request
    assert_equal "Url can't be blank", response.parsed_body["error"]
  end

  test "returns 400 for invalid or unsupported requests" do
    Job.any_instance.stubs(:scan_v2).raises(Job::UnsupportedArchive, "unsupported archive format")

    get api_v2_licenses_path(url: "https://example.com/package.exe")

    assert_response :bad_request
    assert_equal "unsupported archive format", response.parsed_body["error"]
  end

  test "returns 413 when a resource limit is exceeded" do
    Job.any_instance.stubs(:scan_v2).raises(Job::LimitExceeded, "download too large")

    get api_v2_licenses_path(url: "https://example.com/package.zip")

    assert_response :content_too_large
  end

  test "returns a server error when scanning fails" do
    Job.any_instance.stubs(:scan_v2).raises(Job::ScannerError, "scanner failed")

    get api_v2_licenses_path(url: "https://example.com/package.zip")

    assert_response :bad_gateway
  end

  test "scans archives containing bracketed filenames" do
    url = "https://example.com/package.tgz"
    Dir.mktmpdir do |dir|
      source = File.join(dir, "package")
      FileUtils.mkdir_p(File.join(source, "app", "[slug]"))
      File.write(File.join(source, "LICENSE"), "MIT License")
      File.write(File.join(source, "app", "[slug]", "page.tsx"), "export default function Page() {}")
      archive = File.join(dir, "package.tgz")
      assert system("bsdtar", "-czf", archive, "-C", dir, "package")

      Job.any_instance.stubs(:resolve_addresses).returns(["93.184.216.34"])
      stub_request(:get, url).to_return(status: 200, body: File.binread(archive))
    end
    Job.any_instance.expects(:licenses_as_json).with do |root|
      File.file?(File.join(root, "app", "[slug]", "page.tsx"))
    end.returns("schema" => 2, "files" => [], "skipped" => [])

    get api_v2_licenses_path(url: url)

    assert_response :success
    assert_equal url, response.parsed_body["url"]
  end
end
