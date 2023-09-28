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
    it { is_expected.to have_attributes(:config_name => "logstash") }
  end

  describe "a plugin instance with minimal config" do
    subject(:instance) { described_class.new({ "ssl_enabled" => false }) }

    it { is_expected.to respond_to(:register).with(0).arguments }
    it { is_expected.to respond_to(:run).with(1).argument }
    it { is_expected.to respond_to(:stop).with(0).arguments }
    it { is_expected.to respond_to(:close).with(0).arguments }
  end

  describe "plugin register" do
    let(:config) {{ }}

    let(:registered_plugin) { plugin.tap(&:register) }

    context "username and password auth" do
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
    end

    context "SSL disabled" do
      let(:config) { super().merge("ssl_enabled" => false) }

      context "with SSL related configs" do
        let(:config) { super().merge("ssl_keystore_path" => cert_fixture!('client_from_root.jks'), "ssl_certificate_authorities" => cert_fixture!('root.pem')) }

        it "does not allow and raises an error" do
          expected_message = 'Explicit SSL-related settings not supported because `ssl_enabled => false`: ["ssl_keystore_path", "ssl_certificate_authorities"]'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

    end

    context "self identity" do
      let(:config) { super().merge("ssl_enabled" => true) }

      it "requires SSL identity" do
        expected_message = 'SSL identity MUST be configured with either `ssl_certificate`/`ssl_key` or `ssl_keystore_*`'
        expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
      end

      context "SSL certificate" do
        let(:config) { super().merge("ssl_certificate" => cert_fixture!('server_from_root.pem')) }

        context "with keystore" do
          let(:config) { super().merge("ssl_keystore_path" => cert_fixture!('client_from_root.jks')) }

          it "cannot be used together" do
            expected_message = 'SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both'
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end

        context "without `ssl_key`" do
          let(:config) { super().merge("ssl_key_passphrase" => "pa$$w0rd") }

          it "is not allowed" do
            expected_message = '`ssl_key` is required when `ssl_certificate` is configured'
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end
      end

      context "`ssl_key`" do
        let(:config) { super().merge("ssl_key" => cert_fixture!('server_from_root.key.pkcs8.pem')) }

        it "requires SSL certificate" do
          expected_message = '`ssl_key` is not allowed unless `ssl_certificate` is configured'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "`ssl_key_passphrase`" do
        let(:config) { super().merge("ssl_key_passphrase" => "pa$$w0rd") }

        it "requires SSL key" do
          expected_message = '`ssl_key_passphrase` is not allowed unless `ssl_key` is configured'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "`ssl_keystore_path`" do
        let(:config) { super().merge("ssl_keystore_path" => cert_fixture!('server_from_root.jks')) }

        it "requires `ssl_keystore_password`" do
          expected_message = '`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is configured'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "`ssl_keystore_password`" do
        let(:config) { super().merge("ssl_keystore_password" => "pa$$w0rd") }

        it "requires `ssl_keystore_path`" do
          expected_message = '`ssl_keystore_password` is not allowed unless `ssl_keystore_path` is configured'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end
    end

    context "trust with CA" do
      let(:config) { super().merge(
        "ssl_enabled" => true,
        "ssl_certificate_authorities" => cert_fixture!('root.pem'),
        "ssl_keystore_path" => cert_fixture!('server_from_root.jks'),
        "ssl_keystore_password" => "pa$$w0rd"
        # default `ssl_client_authentication` is 'none'
      ) }

      it "requires SSL Client Authentication" do
        expected_message = '`ssl_certificate_authorities` is not supported because `ssl_client_authentication => none`'
        expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
      end
    end
  end
end