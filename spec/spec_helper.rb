require "rspec"
require "rspec/mocks"
require "logstash/devutils/rspec/spec_helper"

module SpecHelper

  def cert_fixture(name)
    File.expand_path("fixtures/certs/generated/#{name}", __dir__)
  end

  def cert_fixture!(name)
    cert_fixture(name).tap do |filename|
      fail "MISSING: #{filename}" unless File.file?(filename)
      fail "UNREADABLE: #{filename}" unless File.readable?(filename)
    end
  end

end

RSpec.configure do |config|
  config.include SpecHelper
end