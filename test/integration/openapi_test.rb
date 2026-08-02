require "test_helper"

class OpenapiTest < ActiveSupport::TestCase
  test 'OpenAPI documents are valid YAML mappings' do
    Dir[Rails.root.join('openapi/api/*/openapi.yaml')].sort.each do |path|
      document = YAML.safe_load_file(path, aliases: true)
      assert_instance_of Hash, document, path
      assert document.key?('openapi'), path
      assert document.key?('paths'), path
    end
  end
end
