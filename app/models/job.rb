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
    when "application/zip"
      destination = File.join([dir, 'zip'])
      `mkdir #{destination} && bsdtar --strip-components=1 -xvf #{path} -C #{destination} > /dev/null 2>&1 `
      results = licensee_as_json(destination)
    when "application/java-archive"
      destination = File.join([dir, 'jar'])
      `mkdir #{destination} && bsdtar -xvf #{path} -C #{destination} > /dev/null 2>&1 `
      results = licensee_as_json(destination)
      results = merge_package_metadata_licenses(results, destination)
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
      license_as_json(license)
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

  def merge_package_metadata_licenses(results, path)
    package_licenses = maven_package_licenses(path)
    return results if package_licenses.empty?

    existing_keys = results[:licenses].map { |license| license[:key] }
    results[:licenses] += package_licenses.reject { |license| existing_keys.include?(license[:key]) }
    results
  end

  def maven_package_licenses(path)
    Dir.glob(File.join(path, 'META-INF', 'maven', '**', 'pom.xml')).flat_map do |pom_path|
      document = Nokogiri::XML(File.read(pom_path))
      document.remove_namespaces!
      document.xpath('//licenses/license/name').map(&:text).flat_map do |license_name|
        licenses_from_expression(license_name)
      end
    end
  end

  def licenses_from_expression(expression)
    expression.scan(/[A-Za-z0-9.-]+/).filter_map do |token|
      token = token.sub(/-or-later\z/i, '')
      license = Licensee.licenses.find { |candidate| candidate.spdx_id.casecmp?(token) || candidate.key.casecmp?(token.downcase) }
      license_as_json(license) if license
    end
  end

  def license_as_json(license)
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

  def download_file(dir)
    path = working_directory(dir)

    conn = Faraday.new do |f|
      f.response :follow_redirects
    end

    response = conn.get(url) do |req|
      req.options.on_data = proc do |chunk, _overall_received_bytes, env|
        if env.status && ![200, 301, 302].include?(env.status)
          raise "Unexpected response status: #{env.status}"
        end
        File.open(path, "ab") { |f| f.write(chunk) }
      end
    end

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
