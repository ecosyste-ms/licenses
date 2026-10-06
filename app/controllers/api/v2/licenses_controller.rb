class Api::V2::LicensesController < Api::V2::ApplicationController
  def show
    job = Job.new(url: params[:url])
    unless job.valid?
      return render json: { error: job.errors.full_messages.to_sentence }, status: :bad_request
    end

    report = job.scan_v2
    response.set_header("Cache-Control", "public, max-age=86400")
    render json: report
  rescue Job::InvalidRequest => error
    render_error(error, :bad_request)
  rescue Job::LimitExceeded => error
    render_error(error, :content_too_large)
  rescue Job::DownloadError, Job::ExtractionError, Job::ScannerError => error
    render_error(error, :bad_gateway)
  end

  private

  def render_error(error, status)
    render json: { error: error.message }, status: status
  end
end
