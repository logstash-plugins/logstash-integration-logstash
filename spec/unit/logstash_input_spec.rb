# encoding: utf-8

require_relative "../spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/inputs/logstash"

describe LogStash::Inputs::Logstash do

  subject(:plugin) { LogStash::Inputs::Logstash.new(config) }

  describe "a plugin class" do
    subject { described_class }

    it { is_expected.to be_a_kind_of Class }
    it { is_expected.to be <= LogStash::Inputs::Base }
    it { is_expected.to have_attributes(:config_name => "logstash_input") }
  end

  describe "a plugin instance with minimal config" do
    subject(:instance) { described_class.new({ "port" => 123, "ssl_enabled" => false }) }

    it { is_expected.to respond_to(:register).with(0).arguments }
    it { is_expected.to respond_to(:run).with(1).argument }
    it { is_expected.to respond_to(:stop).with(0).arguments }
    it { is_expected.to respond_to(:close).with(0).arguments }
  end

  describe "plugin register" do
    let(:config) {{ "port" => 123 }}

    let(:registered_plugin) { plugin.tap(&:register) }

    describe "username and password auth" do
      let(:config) { super().merge("host" => "my-ls-upstream.com", "ssl_enabled" => false) }

      context "with `username`" do
        let(:config) { super().merge("username" => "test_user") }

        it "requires `password`" do
          expected_message = "`password` is REQUIRED when `username` is provided"
          expect{ plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "with `password`" do
        let(:config) { super().merge("password" => "pa$$") }

        it "requires `username`" do
          expected_message = "`password` not allowed unless `username` is configured"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "when `username` is an empty" do
        let(:config) { super().merge("username" => "", "password" => "p$d") }

        it "requires non-empty `username`" do
          expected_message = "Empty `username` or `password` is not allowed"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "when `password` is an empty" do
        let(:config) { super().merge("username" => "test_user", "password" => "") }

        it "requires non-empty `username`" do
          expected_message = "Empty `username` or `password` is not allowed"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end
    end

    context "with SSL disabled" do
      let(:config) { super().merge("ssl_enabled" => false) }

      context "with SSL related configs" do
        let(:config) { super().merge("ssl_keystore_path" => cert_fixture!('client_from_root.jks'), "ssl_certificate_authorities" => cert_fixture!('root.pem')) }

        it "does not allow and raises an error" do
          expected_message = 'Explicit SSL-related settings not supported because `ssl_enabled => false`: ["ssl_keystore_path", "ssl_certificate_authorities"]'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

    end
  end

end