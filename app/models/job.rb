require "digest"
require "fileutils"
require "find"
require "ipaddr"
require "json"
require "net/http"
require "open3"
require "pathname"
require "set"
require "socket"
require "tempfile"
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
  MAX_LISTING_LINE_BYTES = (MAX_ARCHIVE_PATH_BYTES * 4) + 4096
  ARCHIVE_COMMAND_TIMEOUT = 60
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

  LISTING_ESCAPES = {
    "\\" => "\\",
    "a" => "\a",
    "b" => "\b",
    "f" => "\f",
    "n" => "\n",
    "r" => "\r",
    "t" => "\t",
    "v" => "\v"
  }.freeze
  EXPRESSION_OPERATORS = %w[AND OR].freeze
  UNASSERTED_LICENSES = %w[NOASSERTION NONE].freeze

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
    attributions = attribution_files(scan.report, scan.root)
    v1_results(scan.report, attributions.files)
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
    invalid_names = [".", "..", File::SEPARATOR, File::ALT_SEPARATOR].compact
    if name.blank? || invalid_names.include?(name)
      raise InvalidRequest, "URL must include an archive filename"
    end

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
      Tempfile.create("archive-entries") do |list|
        list.binmode
        regular_entries.each { |entry| list.write(literal_pattern(entry[:name]), "\0") }
        list.flush

        run_archive_command(
          "bsdtar", "-xmf", path, "-C", destination, "--null", "-T", list.path,
          rlimit_fsize: MAX_EXPANDED_FILE_BYTES
        ) { |stdout| stdout.read }
      end
    end

    verify_extracted_files!(destination)
    skipped = entries.filter_map do |entry|
      next if entry[:regular] || entry[:directory]

      { "path" => display_path(entry[:clean_name]), "reason" => "non-regular" }
    end
    Extraction.new(root: common_extraction_root(destination), skipped: skipped)
  rescue Errno::ENOENT => error
    raise ExtractionError, "bsdtar executable not found: #{error.message}"
  end

  def archive_entries(path)
    entries = []
    clean_names = Set.new
    path_bytes = 0
    total_size = 0

    each_archive_listing(path) do |name, line|
      if entries.length >= MAX_ARCHIVE_ENTRIES
        raise LimitExceeded, "archive contains more than #{MAX_ARCHIVE_ENTRIES} entries"
      end

      path_bytes += name.bytesize
      if path_bytes > MAX_ARCHIVE_PATH_BYTES
        raise LimitExceeded, "archive paths exceed #{MAX_ARCHIVE_PATH_BYTES} bytes"
      end

      entry = parse_archive_entry(line, name)
      raise ExtractionError, "archive contains duplicate paths" unless clean_names.add?(entry[:clean_name])

      if entry[:regular]
        if entry[:size] > MAX_EXPANDED_FILE_BYTES
          raise LimitExceeded,
            "archive entry exceeds #{MAX_EXPANDED_FILE_BYTES} bytes: #{display_path(entry[:clean_name])}"
        end

        total_size += entry[:size]
        if total_size > MAX_EXPANDED_BYTES
          raise LimitExceeded, "expanded archive exceeds #{MAX_EXPANDED_BYTES} bytes"
        end
      end

      entries << entry
    end

    entries
  end

  # Streams the name and detail listings in lockstep so limits are enforced
  # before the whole listing is buffered.
  def each_archive_listing(path)
    run_archive_command("bsdtar", "-tf", path) do |names|
      run_archive_command("bsdtar", "-tvf", path) do |details|
        loop do
          name = read_listing_line(names)
          detail = read_listing_line(details)
          break if name.nil? && detail.nil?
          raise ExtractionError, "inconsistent archive listing" if name.nil? || detail.nil?

          yield unescape_listing(name), detail
        end
      end
    end
  end

  def read_listing_line(io)
    line = io.gets("\n", MAX_LISTING_LINE_BYTES)
    return if line.nil?
    raise LimitExceeded, "archive paths exceed #{MAX_ARCHIVE_PATH_BYTES} bytes" unless line.end_with?("\n")

    line.chomp
  end

  # bsdtar escapes backslashes and non-printable bytes when listing entries.
  def unescape_listing(name)
    name.b.gsub(/\\(?:([0-7]{3})|(.))/n) do
      next Regexp.last_match(1).to_i(8).chr if Regexp.last_match(1)

      LISTING_ESCAPES.fetch(Regexp.last_match(2)) { raise ExtractionError, "unable to parse archive listing" }.b
    end
  end

  # bsdtar treats selected names as patterns, so glob characters must be escaped.
  def literal_pattern(name)
    name.gsub(/[\\*?\[\]]/n) { |character| "\\#{character}" }
  end

  def display_path(name)
    name.dup.force_encoding(Encoding::UTF_8).scrub
  end

  def run_archive_command(*command, **options)
    Tempfile.create("archive-command") do |stderr|
      stdin, stdout, wait_thread = Open3.popen2(
        { "LC_ALL" => "C" },
        *command,
        err: stderr,
        pgroup: true,
        **options
      )
      stdin.close
      stdout.binmode
      timed_out = false
      timer = Thread.new do
        sleep ARCHIVE_COMMAND_TIMEOUT
        timed_out = true
        terminate_process_group(wait_thread.pid)
      end

      begin
        result = yield stdout
        status = wait_thread.value
      rescue StandardError
        raise archive_timeout_error if timed_out

        raise
      ensure
        timer.kill
        timer.join
        terminate_process_group(wait_thread.pid) if wait_thread.alive?
        stdout.close
        wait_thread.join
      end

      raise archive_timeout_error if timed_out
      unless status.success?
        if status.signaled? && status.termsig == Signal.list["XFSZ"]
          raise LimitExceeded, "expanded file exceeds #{MAX_EXPANDED_FILE_BYTES} bytes"
        end

        stderr.rewind
        message = display_path(stderr.read(4096).to_s).strip
        raise ExtractionError, message.presence || "unable to read archive"
      end

      result
    end
  end

  def archive_timeout_error
    LimitExceeded.new("archive processing exceeded #{ARCHIVE_COMMAND_TIMEOUT} seconds")
  end

  def terminate_process_group(pid)
    Process.kill("KILL", -pid)
  rescue Errno::ESRCH, Errno::EPERM
    nil
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
      raise ExtractionError, "archive contains an absolute path: #{display_path(name)}"
    end

    cleaned = Pathname.new(normalized).cleanpath.to_s
    if cleaned == ".." || cleaned.start_with?("../")
      raise ExtractionError, "archive contains a traversal path: #{display_path(name)}"
    end

    depth = cleaned.split("/").reject { |part| part == "." }.length
    if depth > MAX_ARCHIVE_PATH_DEPTH
      raise LimitExceeded, "archive path exceeds #{MAX_ARCHIVE_PATH_DEPTH} levels: #{display_path(name)}"
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

      content = decode_attribution(contents, file["encoding"])
      if content.bytesize > remaining_bytes
        skipped << { "path" => file["path"], "reason" => "attribution-limit" }
        next
      end

      records << {
        "path" => file["path"],
        "roles" => roles,
        "sha256" => file["sha256"],
        "encoding" => file["encoding"],
        "content" => content
      }
      remaining_bytes -= content.bytesize
    end

    Attributions.new(files: records, skipped: skipped)
  end

  def v1_results(report, attribution_files)
    contents = attribution_files.to_h { |file| [file["path"], file["content"]] }
    license_paths = {}
    matched_files = []

    expressions = Array(report["expressions"]).reject { |expression| expression["identification"] == "NOASSERTION" }
    expressions.sort_by.with_index { |expression, index| [expression["root"] ? 0 : 1, index] }.each do |expression|
      expression_license_ids(expression["expression"]).each { |id| license_paths[id] = nil unless license_paths.key?(id) }
    end

    Array(report["files"]).each do |file|
      next if Array(file["roles"]).empty?

      detections = Array(file["detections"]).reject { |detection| detection["identification"] == "NOASSERTION" }
      detections.flat_map { |detection| detection_license_ids(detection) }.each do |id|
        license_paths[id] ||= file["path"]
      end
      matched_files << {
        filename: file["path"],
        confidence: match_confidence(file, detections),
        content: contents[file["path"]]
      }
    end

    Array(report["declared"]).each do |declared|
      expression_license_ids(declared["normalized_expression"]).each do |id|
        license_paths[id] = nil unless license_paths.key?(id)
      end
    end

    licenses = license_paths.map do |id, path|
      {
        key: id.downcase,
        name: id,
        source: id,
        description: id,
        content: contents[path],
        permissions: id,
        conditions: id,
        limitations: id
      }
    end

    { licenses: licenses, matched_files: matched_files }
  end

  def detection_license_ids(detection)
    ids = Array(detection["matches"]).flat_map { |match| Array(match["license_ids"]) }
    ids = expression_license_ids(detection["expression"]) if ids.empty?
    ids.reject { |id| id.blank? || UNASSERTED_LICENSES.include?(id) }.uniq
  end

  def expression_license_ids(expression)
    expression.to_s.gsub(/\s+WITH\s+[^\s()]+/i, " ").split(/[\s()]+/).filter_map do |token|
      id = token.delete_suffix("+")
      next if id.blank? || EXPRESSION_OPERATORS.include?(id.upcase) || UNASSERTED_LICENSES.include?(id)

      id
    end.uniq
  end

  def match_confidence(file, detections)
    scores = detections.flat_map { |detection| Array(detection["matches"]).filter_map { |match| match["score"] } }
    scores.max || file["license_text_coverage"]
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
    current_uri = uri

    loop do
      redirected = download_response(current_uri, destination, digest)
      return unless redirected

      raise DownloadError, "redirect limit exceeded" if redirects_remaining.zero?

      redirects_remaining -= 1
      current_uri = redirected
    end
  end

  def download_response(uri, destination, digest)
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
    redirected = nil
    http.start do
      http.request(request) do |response|
        case response
        when Net::HTTPSuccess
          write_response(response, destination, digest)
        when Net::HTTPRedirection
          location = response["location"]
          raise DownloadError, "redirect is missing a location" if location.blank?

          redirected = validated_uri(URI.join(uri.to_s, location).to_s)
        else
          raise DownloadError, "unexpected response status: #{response.code}"
        end
      end
    end
    redirected
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
    root = File.expand_path(dir)
    path = File.expand_path(basename, root)
    unless path.start_with?("#{root}#{File::SEPARATOR}")
      raise InvalidRequest, "archive filename escapes the working directory"
    end

    path
  end
end
