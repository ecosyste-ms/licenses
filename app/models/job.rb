require "digest"
require "fileutils"
require "find"
require "ipaddr"
require "json"
require "net/http"
require "open3"
require "pathname"
require "socket"
require "timeout"
require "uri"

class Job < ApplicationRecord
  class InvalidRequest < StandardError; end
  class UnsupportedArchive < InvalidRequest; end
  class LimitExceeded < StandardError; end
  class DownloadError < StandardError; end
  class ExtractionError < StandardError; end
  class ScannerError < StandardError; end

  Extraction = Data.define(:root, :skipped)
  Scan = Data.define(:report, :root, :skipped)
  Attributions = Data.define(:files, :skipped)

  MAX_DOWNLOAD_BYTES = 100.megabytes
  MAX_ARCHIVE_ENTRIES = 10_000
  MAX_ARCHIVE_PATH_DEPTH = 64
  MAX_ARCHIVE_PATH_BYTES = 1.megabyte
  MAX_EXPANDED_FILE_BYTES = 32.megabytes
  MAX_EXPANDED_BYTES = 512.megabytes
  MAX_ATTRIBUTION_FILES = 100
  MAX_ATTRIBUTION_BYTES = 5.megabytes
  MAX_REDIRECTS = 5
  LICENSES_MAX_FILES = 10_000
  HTTP_OPEN_TIMEOUT = 5
  HTTP_READ_TIMEOUT = 30
  HTTP_WRITE_TIMEOUT = 30
  HTTP_REQUEST_TIMEOUT = 60

  BLOCKED_IP_RANGES = %w[
    0.0.0.0/8
    10.0.0.0/8
    100.64.0.0/10
    127.0.0.0/8
    169.254.0.0/16
    172.16.0.0/12
    192.0.0.0/24
    192.0.2.0/24
    192.168.0.0/16
    198.18.0.0/15
    198.51.100.0/24
    203.0.113.0/24
    224.0.0.0/4
    240.0.0.0/4
    ::/128
    ::1/128
    64:ff9b::/96
    100::/64
    2001:db8::/32
    fc00::/7
    fe80::/10
    ff00::/8
  ].map { |range| IPAddr.new(range) }.freeze

  validates_presence_of :url
  validates_uniqueness_of :id

  scope :status, ->(status) { where(status: status) }

  def self.check_statuses
    Job.where(status: ["queued", "working"]).find_each(&:check_status)
  end

  def check_status
    return if sidekiq_id.blank?
    return if finished?

    update(status: fetch_status)
  end

  def fetch_status
    Sidekiq::Status.status(sidekiq_id).presence || "error"
  end

  def finished?
    ["complete", "error"].include?(status)
  end

  def parse_licenses_async
    sidekiq_id = ParseLicensesWorker.perform_async(id)
    update(sidekiq_id: sidekiq_id)
  end

  def perform_license_parsing
    Dir.mktmpdir do |dir|
      sha256 = download_file(dir)
      results = parse_licenses(dir)
      update!(results: results, status: "complete", sha256: sha256)
    end
  rescue => error
    update(results: { error: error.inspect }, status: "error")
  end

  def scan_v2
    Dir.mktmpdir do |dir|
      sha256 = download_file(dir)
      scan = scan_archive(dir)
      attributions = attribution_files(scan.report, scan.root)
      report = scan.report.merge(
        "url" => url,
        "sha256" => sha256,
        "attribution_files" => attributions.files
      )
      report["skipped"] = sorted_skipped(Array(report["skipped"]) + scan.skipped + attributions.skipped)
      report
    end
  end

  def parse_licenses(dir)
    scan = scan_archive(dir)
    scan.report["skipped"] = sorted_skipped(Array(scan.report["skipped"]) + scan.skipped)
    scan.report
  end

  def scan_archive(dir)
    extraction = extract_archive(working_directory(dir), dir)
    report = licenses_as_json(extraction.root)
    Scan.new(report: report, root: extraction.root, skipped: extraction.skipped)
  end

  def licenses_as_json(path)
    command = ENV.fetch("LICENSES_COMMAND", "licenses")
    stdout, stderr, status = Open3.capture3(
      command,
      "-json",
      "-max-files",
      LICENSES_MAX_FILES.to_s,
      path
    )

    unless [0, 2, 3].include?(status.exitstatus)
      message = stderr.to_s.strip.presence || "licenses exited with status #{status.exitstatus}"
      raise ScannerError, message
    end

    report = JSON.parse(stdout)
    raise ScannerError, "licenses returned a non-object report" unless report.is_a?(Hash)

    report
  rescue JSON::ParserError => error
    raise ScannerError, "licenses returned invalid JSON: #{error.message}"
  rescue Errno::ENOENT => error
    raise ScannerError, "licenses executable not found: #{error.message}"
  end

  def download_file(dir)
    destination = working_directory(dir)
    uri = validated_uri(url)
    digest = Digest::SHA256.new

    Timeout.timeout(HTTP_REQUEST_TIMEOUT) do
      download_uri(uri, destination, digest, MAX_REDIRECTS)
    end
    digest.hexdigest
  rescue InvalidRequest, LimitExceeded, DownloadError
    FileUtils.rm_f(destination) if destination
    raise
  rescue => error
    FileUtils.rm_f(destination) if destination
    raise DownloadError, error.message
  end

  def basename
    uri = validated_uri(url)
    name = File.basename(uri.path.to_s)
    raise InvalidRequest, "URL must include an archive filename" if name.blank? || name == "."

    name
  end

  private

  def extract_archive(path, dir)
    case archive_type(path)
    when :gem
      extract_gem(path, dir)
    when :zip, :tar
      destination = File.join(dir, "archive")
      extract_with_bsdtar(path, destination)
    else
      raise UnsupportedArchive, "unsupported archive format"
    end
  end

  def extract_gem(path, dir)
    envelope = File.join(dir, "gem")
    extraction = extract_with_bsdtar(path, envelope)
    payload = File.join(extraction.root, "data.tar.gz")
    unless File.file?(payload) && !File.symlink?(payload)
      raise ExtractionError, "Ruby gem does not contain data.tar.gz"
    end

    destination = File.join(dir, "archive")
    extract_with_bsdtar(payload, destination)
  end

  def archive_type(path)
    name = basename.downcase
    return :gem if name.end_with?(".gem")
    return :zip if name.end_with?(".zip", ".jar")
    return :tar if name.end_with?(".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz")

    case mime_type(path)
    when "application/zip", "application/java-archive"
      :zip
    when "application/gzip", "application/x-gzip", "application/x-tar", "application/x-xz"
      :tar
    end
  end

  def extract_with_bsdtar(path, destination)
    entries = archive_entries(path)
    regular_entries = entries.select { |entry| entry[:regular] }
    FileUtils.mkdir_p(destination)

    unless regular_entries.empty?
      arguments = ["bsdtar", "-xmf", path, "-C", destination, "--"]
      arguments.concat(regular_entries.map { |entry| entry[:name] })
      _stdout, stderr, status = Open3.capture3(*arguments, rlimit_fsize: MAX_EXPANDED_FILE_BYTES)
      unless status.success?
        if status.signaled? && status.termsig == Signal.list["XFSZ"]
          raise LimitExceeded, "expanded file exceeds #{MAX_EXPANDED_FILE_BYTES} bytes"
        end
        raise ExtractionError, stderr.to_s.strip.presence || "bsdtar extraction failed"
      end
    end

    verify_extracted_files!(destination)
    skipped = entries.filter_map do |entry|
      next if entry[:regular] || entry[:directory]

      { "path" => entry[:clean_name], "reason" => "non-regular" }
    end
    Extraction.new(root: common_extraction_root(destination), skipped: skipped)
  rescue Errno::ENOENT => error
    raise ExtractionError, "bsdtar executable not found: #{error.message}"
  end

  def archive_entries(path)
    names = archive_listing(path, "-tf").lines.map(&:chomp)
    details = archive_listing(path, "-tvf").lines
    raise ExtractionError, "inconsistent archive listing" unless names.length == details.length

    entries = details.zip(names).map { |line, name| parse_archive_entry(line, name) }
    if entries.length > MAX_ARCHIVE_ENTRIES
      raise LimitExceeded, "archive contains more than #{MAX_ARCHIVE_ENTRIES} entries"
    end

    path_bytes = entries.sum { |entry| entry[:name].bytesize }
    if path_bytes > MAX_ARCHIVE_PATH_BYTES
      raise LimitExceeded, "archive paths exceed #{MAX_ARCHIVE_PATH_BYTES} bytes"
    end

    duplicates = entries.group_by { |entry| entry[:clean_name] }.select { |_name, group| group.length > 1 }
    raise ExtractionError, "archive contains duplicate paths" if duplicates.any?

    regular_entries = entries.select { |entry| entry[:regular] }
    oversized = regular_entries.find { |entry| entry[:size] > MAX_EXPANDED_FILE_BYTES }
    if oversized
      raise LimitExceeded, "archive entry exceeds #{MAX_EXPANDED_FILE_BYTES} bytes: #{oversized[:clean_name]}"
    end

    total_size = regular_entries.sum { |entry| entry[:size] }
    if total_size > MAX_EXPANDED_BYTES
      raise LimitExceeded, "expanded archive exceeds #{MAX_EXPANDED_BYTES} bytes"
    end

    entries
  end

  def archive_listing(path, flag)
    stdout, stderr, status = Open3.capture3({ "LC_ALL" => "C" }, "bsdtar", flag, path)
    return stdout if status.success?

    raise ExtractionError, stderr.to_s.strip.presence || "unable to read archive"
  end

  def parse_archive_entry(line, name)
    fields = line.strip.split(/\s+/, 9)
    raise ExtractionError, "unable to parse archive listing" unless fields.length == 9

    mode, _links, _owner, _group, size, _month, _day, _time, _display_name = fields
    clean_name = safe_archive_path(name)
    {
      name: name,
      clean_name: clean_name,
      size: Integer(size, 10),
      regular: mode.start_with?("-"),
      directory: mode.start_with?("d")
    }
  rescue ArgumentError
    raise ExtractionError, "unable to parse archive listing"
  end

  def safe_archive_path(name)
    if name.blank? || name.include?("\0") || name.include?("\n") || name.include?("\r")
      raise ExtractionError, "archive contains an invalid path"
    end

    normalized = name.tr("\\", "/")
    if normalized.start_with?("/") || normalized.match?(/\A[A-Za-z]:/)
      raise ExtractionError, "archive contains an absolute path: #{name}"
    end

    cleaned = Pathname.new(normalized).cleanpath.to_s
    if cleaned == ".." || cleaned.start_with?("../")
      raise ExtractionError, "archive contains a traversal path: #{name}"
    end

    depth = cleaned.split("/").reject { |part| part == "." }.length
    if depth > MAX_ARCHIVE_PATH_DEPTH
      raise LimitExceeded, "archive path exceeds #{MAX_ARCHIVE_PATH_DEPTH} levels: #{name}"
    end

    cleaned
  end

  def verify_extracted_files!(destination)
    root = File.expand_path(destination)
    total_size = 0

    Find.find(destination) do |path|
      next if path == destination

      expanded = File.expand_path(path)
      unless expanded.start_with?("#{root}#{File::SEPARATOR}")
        raise ExtractionError, "archive escaped the extraction directory"
      end

      stat = File.lstat(path)
      if stat.symlink? || (!stat.directory? && !stat.file?)
        FileUtils.rm_rf(path)
        next
      end
      next if stat.directory?

      if stat.size > MAX_EXPANDED_FILE_BYTES
        raise LimitExceeded, "expanded file exceeds #{MAX_EXPANDED_FILE_BYTES} bytes"
      end
      total_size += stat.size
      if total_size > MAX_EXPANDED_BYTES
        raise LimitExceeded, "expanded archive exceeds #{MAX_EXPANDED_BYTES} bytes"
      end
    end
  end

  def common_extraction_root(destination)
    files = Dir.glob(File.join(destination, "**", "*"), File::FNM_DOTMATCH).select do |path|
      File.file?(path) && !File.symlink?(path)
    end
    return destination if files.empty?

    relative_paths = files.map do |path|
      Pathname.new(path).relative_path_from(Pathname.new(destination)).each_filename.to_a
    end
    first_component = relative_paths.first.first
    if first_component.present? && relative_paths.all? { |parts| parts.length > 1 && parts.first == first_component }
      File.join(destination, first_component)
    else
      destination
    end
  end

  def attribution_files(report, root)
    remaining_bytes = MAX_ATTRIBUTION_BYTES
    records = []
    skipped = []

    Array(report["files"]).each do |file|
      roles = Array(file["roles"])
      next if roles.empty?

      if records.length >= MAX_ATTRIBUTION_FILES
        skipped << { "path" => file["path"], "reason" => "attribution-limit" }
        next
      end

      path = safe_report_file(root, file["path"])
      unless path
        skipped << { "path" => file["path"], "reason" => "attribution-unavailable" }
        next
      end

      contents = File.binread(path)
      if contents.bytesize > remaining_bytes
        skipped << { "path" => file["path"], "reason" => "attribution-limit" }
        next
      end

      records << {
        "path" => file["path"],
        "roles" => roles,
        "sha256" => file["sha256"],
        "encoding" => file["encoding"],
        "content" => decode_attribution(contents, file["encoding"])
      }
      remaining_bytes -= contents.bytesize
    end

    Attributions.new(files: records, skipped: skipped)
  end

  def sorted_skipped(records)
    records.sort_by { |record| [record["path"].to_s, record["reason"].to_s] }
  end

  def safe_report_file(root, relative_path)
    return if relative_path.blank?

    expanded_root = File.expand_path(root)
    path = File.expand_path(relative_path, expanded_root)
    return unless path.start_with?("#{expanded_root}#{File::SEPARATOR}")
    return unless File.file?(path) && !File.symlink?(path)

    path
  end

  def decode_attribution(contents, encoding)
    case encoding
    when "utf-16le"
      contents.delete_prefix("\xFF\xFE".b).force_encoding(Encoding::UTF_16LE).encode(Encoding::UTF_8)
    when "utf-16be"
      contents.delete_prefix("\xFE\xFF".b).force_encoding(Encoding::UTF_16BE).encode(Encoding::UTF_8)
    when "iso-8859-1"
      contents.force_encoding(Encoding::ISO_8859_1).encode(Encoding::UTF_8)
    else
      contents.delete_prefix("\xEF\xBB\xBF".b).force_encoding(Encoding::UTF_8).scrub
    end
  end

  def validated_uri(value)
    uri = URI.parse(value.to_s)
    unless uri.is_a?(URI::HTTP) && %w[http https].include?(uri.scheme) && uri.host.present?
      raise InvalidRequest, "URL must use HTTP or HTTPS"
    end
    raise InvalidRequest, "URL must not contain credentials" if uri.userinfo.present?

    uri
  rescue URI::InvalidURIError => error
    raise InvalidRequest, "invalid URL: #{error.message}"
  end

  def download_uri(uri, destination, digest, redirects_remaining)
    addresses = resolve_addresses(uri.host, uri.port)
    raise DownloadError, "hostname did not resolve" if addresses.empty?
    raise InvalidRequest, "URL resolves to a blocked address" if addresses.any? { |address| blocked_address?(address) }

    http = Net::HTTP.new(uri.host, uri.port, nil)
    http.ipaddr = addresses.first
    http.use_ssl = uri.scheme == "https"
    http.open_timeout = HTTP_OPEN_TIMEOUT
    http.read_timeout = HTTP_READ_TIMEOUT
    http.write_timeout = HTTP_WRITE_TIMEOUT

    request = Net::HTTP::Get.new(uri.request_uri, "User-Agent" => "licenses.ecosyste.ms")
    http.start do
      http.request(request) do |response|
        case response
        when Net::HTTPSuccess
          write_response(response, destination, digest)
        when Net::HTTPRedirection
          raise DownloadError, "redirect limit exceeded" if redirects_remaining.zero?

          location = response["location"]
          raise DownloadError, "redirect is missing a location" if location.blank?

          redirected = validated_uri(URI.join(uri.to_s, location).to_s)
          download_uri(redirected, destination, digest, redirects_remaining - 1)
        else
          raise DownloadError, "unexpected response status: #{response.code}"
        end
      end
    end
  end

  def write_response(response, destination, digest)
    content_length = response["content-length"].to_i
    if content_length > MAX_DOWNLOAD_BYTES
      raise LimitExceeded, "download exceeds #{MAX_DOWNLOAD_BYTES} bytes"
    end

    received = 0
    File.open(destination, "wb") do |file|
      response.read_body do |chunk|
        received += chunk.bytesize
        if received > MAX_DOWNLOAD_BYTES
          raise LimitExceeded, "download exceeds #{MAX_DOWNLOAD_BYTES} bytes"
        end
        digest.update(chunk)
        file.write(chunk)
      end
    end
  end

  def resolve_addresses(host, port)
    Addrinfo.getaddrinfo(host, port, nil, :STREAM).map(&:ip_address).uniq
  rescue SocketError => error
    raise DownloadError, "unable to resolve hostname: #{error.message}"
  end

  def blocked_address?(address)
    ip = IPAddr.new(address)
    ip = ip.native if ip.ipv4_mapped?
    BLOCKED_IP_RANGES.any? { |range| range.include?(ip) }
  rescue IPAddr::InvalidAddressError
    true
  end

  def mime_type(path)
    IO.popen(
      ["file", "--brief", "--mime-type", path],
      in: :close,
      err: :close
    ) { |io| io.read.chomp }
  end

  def working_directory(dir)
    File.join(dir, basename)
  end
end
