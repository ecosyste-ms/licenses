module ApplicationHelper
  def meta_title
    [@meta_title, 'Ecosyste.ms: Licenses'].compact.join(' | ')
  end

  def meta_description
    @meta_description || app_description
  end

  def app_name
    "Licenses"
  end

  def app_description
    'An open API service to parse license metadata from many open source software ecosystems.'
  end
end
