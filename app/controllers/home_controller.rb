class HomeController < ApplicationController
  def index
    @licenses = Job.licenses
  end
end