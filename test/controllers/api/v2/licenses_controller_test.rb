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
end
