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

  test "rejects oversized redirect bodies instead of buffering them" do
    redirect_body = "x" * 1.megabyte
    with_http_server(
      "/package.zip" => [302, { "Location" => "/final.zip" }, redirect_body],
      "/final.zip" => [200, {}, file_fixture("main.zip").binread]
    ) do |base_url, requests|
      Job.any_instance.stubs(:blocked_address?).returns(false)
      Job.any_instance.expects(:licenses_as_json).never

      stub_const(Job, :MAX_DOWNLOAD_BYTES, 100.kilobytes) do
        get api_v2_licenses_path(url: "#{base_url}/package.zip")
      end

      assert_response :content_too_large
      assert_equal "redirect response exceeds #{100.kilobytes} bytes", response.parsed_body["error"]
      assert_equal ["/package.zip"], requests
    end
  end

  test "follows redirects with small bodies from a real server" do
    with_http_server(
      "/package.zip" => [302, { "Location" => "/final.zip" }, "Moved"],
      "/final.zip" => [200, {}, file_fixture("main.zip").binread]
    ) do |base_url, requests|
      Job.any_instance.stubs(:blocked_address?).returns(false)
      Job.any_instance.expects(:licenses_as_json).returns("schema" => 2, "files" => [], "skipped" => [])

      get api_v2_licenses_path(url: "#{base_url}/package.zip")

      assert_response :success
      assert_equal "546b13eb945186f67d2480910dce773ca0e2539b80cadafe7bb2fe3c537800ec", response.parsed_body["sha256"]
      assert_equal ["/package.zip", "/final.zip"], requests
    end
  end

  private

  # Serves canned responses without a Content-Length so bodies are read until
  # the connection closes, exercising the streaming limit.
  def with_http_server(routes)
    server = TCPServer.new("127.0.0.1", 0)
    requests = []
    thread = Thread.new do
      loop do
        client = server.accept
        begin
          path = client.gets.to_s.split[1]
          nil until client.gets.to_s.strip.empty?
          requests << path
          status, headers, body = routes.fetch(path, [404, {}, ""])
          client.write("HTTP/1.1 #{status} #{Rack::Utils::HTTP_STATUS_CODES[status]}\r\n")
          headers.merge("Connection" => "close").each { |name, value| client.write("#{name}: #{value}\r\n") }
          client.write("\r\n")
          client.write(body)
        rescue IOError, SystemCallError
          nil
        ensure
          client.close
        end
      end
    end

    WebMock.disable_net_connect!(allow_localhost: true)
    yield "http://127.0.0.1:#{server.addr[1]}", requests
  ensure
    WebMock.disable_net_connect!
    thread&.kill
    server&.close
  end
end
