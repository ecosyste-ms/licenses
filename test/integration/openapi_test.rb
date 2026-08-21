require "test_helper"

class OpenapiTest < ActiveSupport::TestCase
  test 'OpenAPI documents are valid YAML objects' do
    %w[v1 v2].each do |version|
      document = YAML.load_file(Rails.root.join("openapi/api/#{version}/openapi.yaml"))
      assert_instance_of Hash, document
      assert_equal "3.0.1", document["openapi"]
    end
  end
end
