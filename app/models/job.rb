class Job < ApplicationRecord
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
    Sidekiq::Status.status(sidekiq_id).presence || 'error'
  end

  def finished?
    ['complete', 'error'].include?(status)
  end

  def parse_licenses_async
    sidekiq_id = ParseLicensesWorker.perform_async(id)
    update(sidekiq_id: sidekiq_id)
  end

  def perform_license_parsing
    begin
      Dir.mktmpdir do |dir|
        sha256 = download_file(dir)
        results = parse_licenses(dir)
        update!(results: results, status: 'complete', sha256: sha256)
      end
    rescue => e
      update(results: {error: e.inspect}, status: 'error')
    end
  end

  def parse_licenses(dir)
    path = working_directory(dir)

    case mime_type(path)
    when "application/zip", "application/java-archive"
      destination = File.join([dir, 'zip'])
      `mkdir #{destination} && bsdtar --strip-components=1 -xvf #{path} -C #{destination} > /dev/null 2>&1 `
      results = licensee_as_json(destination)
    when "application/gzip"
      destination = File.join([dir, 'tar'])
      `mkdir #{destination} && tar xzf #{path} -C #{destination} --strip-components 1`
      results = licensee_as_json(destination)
    else
      results = []
    end

    return results
  end

  def licensee_as_json(path)
    project = Licensee::Projects::FSProject.new path, detect_readme: true
    licenses = project.licenses.map do |license|
      {
        key: license.key,
        name: license.name,
        source: license.name,
        description: license.name,
        content: license.content,
        permissions: license.name,
        conditions: license.name,
        limitations: license.name
      }
    end
    matched_files = project.matched_files.map do |file|
      {
        filename: file.filename,
        confidence: file.confidence,
        content: file.content
      }
    end
    {
      licenses: licenses,
      matched_files: matched_files
    }
  end

  def download_file(dir)
    path = working_directory(dir)
    downloaded_file = File.open(path, "wb")

    request = Typhoeus::Request.new(url, followlocation: true)
    request.on_headers do |response|
      return nil unless [200,301,302].include? response.code
    end
    request.on_body { |chunk| downloaded_file.write(chunk) }
    request.on_complete { downloaded_file.close }
    request.run

    return Digest::SHA256.hexdigest File.read(path)
  end

  def mime_type(path)
    IO.popen(
      ["file", "--brief", "--mime-type", path],
      in: :close, err: :close
    ) { |io| io.read.chomp }
  end

  def working_directory(dir)
    File.join([dir, basename])
  end

  def basename
    File.basename(url)
  end

  def self.licenses
    Licensee.licenses
  end
end
