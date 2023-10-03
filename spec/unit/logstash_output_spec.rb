# encoding: utf-8

require_relative "../spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/outputs/logstash"

describe LogStash::Outputs::Logstash do

  let(:config) {{ "hosts" => "127.0.0.1" }}

  subject(:plugin) { LogStash::Outputs::Logstash.new(config) }

  describe "a plugin class" do
    subject { described_class }

    it { is_expected.to be_a_kind_of Class }
    it { is_expected.to be <= LogStash::Outputs::Base }
    it { is_expected.to have_attributes(:config_name => "logstash") }
  end

  describe "a plugin instance with minimal config" do
    subject(:instance) { described_class.new(config) }

    it { is_expected.to respond_to(:register).with(0).arguments }
    it { is_expected.to respond_to(:multi_receive).with(1).argument }
    it { is_expected.to respond_to(:stop).with(0).arguments }
    it { is_expected.to respond_to(:close).with(0).arguments }
  end

  describe "plugin register" do
    let(:registered_plugin) { plugin.tap(&:register) }

    describe "construct host URI" do

      it "applies default https scheme and 9800 port" do
        expect(registered_plugin.construct_host_uri.eql?(::LogStash::Util::SafeURI.new("https://127.0.0.1:9800/"))).to be_truthy
      end

      describe "SSL disabled" do
        let(:config) { super().merge("ssl_enabled" => false) }

        it "causes HTTP scheme" do
          expect(registered_plugin.construct_host_uri.eql?(::LogStash::Util::SafeURI.new("http://127.0.0.1:9800/"))).to be_truthy
        end
      end

      describe "custom port" do
        let(:config) { super().merge("hosts" => "127.0.0.1:9808") }

        it "will be applied" do
          expect(registered_plugin.construct_host_uri.eql?(::LogStash::Util::SafeURI.new("https://127.0.0.1:9808/"))).to be_truthy
        end
      end
    end

    describe "username and password auth" do
      let(:config) { super().merge("hosts" => "my-ls-downstream.com:1234", "ssl_enabled" => false) }

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

      context "SSL certificate" do
        let(:config) { super().merge("ssl_certificate" => cert_fixture!('server_from_root.pem')) }

        it "requires `ssl_key`" do
          expected_message = '`ssl_key` is REQUIRED when `ssl_certificate` is provided'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end

        context "with keystore" do
          let(:config) { super().merge("ssl_keystore_path" => cert_fixture!('client_from_root.jks')) }

          it "cannot be used together" do
            expected_message = 'SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both'
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

      context "`ssl_keystore_path`" do
        let(:config) { super().merge("ssl_keystore_path" => cert_fixture!('server_from_root.jks')) }

        it "requires `ssl_keystore_password`" do
          expected_message = '`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is provided'
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

    context "trust" do
      let(:config) { super().merge("ssl_enabled" => true) }

      context "with CA" do
        let(:config) { super().merge("ssl_certificate_authorities" => cert_fixture!('root.pem')) }

        context "and `ssl_verification_mode` is 'none'" do
          let(:config) { super().merge("ssl_verification_mode" => "none") }

          it "not allowed" do
            expected_message = 'SSL Certificate Authorities cannot be configured when `ssl_verification_mode => none`'
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end

        context "and truststore" do
          let(:config) { super().merge("ssl_truststore_path" => cert_fixture!('client_self_signed.jks')) }

          it "not allowed" do
            expected_message = 'SSL trust can be configured with EITHER `ssl_certificate_authorities` OR `ssl_truststore_*`, but not both'
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end
      end

      context "truststore" do
        let(:config) { super().merge("ssl_truststore_path" => cert_fixture!('client_self_signed.jks')) }

        it "requires truststore password" do
          expected_message = '`ssl_truststore_password` is REQUIRED when `ssl_truststore_path` is provided'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end

        context "and `ssl_verification_mode` is 'none'" do
          let(:config) { super().merge("ssl_verification_mode" => "none") }

          it "not allowed" do
            expected_message = 'SSL Truststore cannot be configured when `ssl_verification_mode => none`'
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end
      end

      context "password without truststore path" do
        let(:config) { super().merge("ssl_truststore_password" => "pa$$w0rd") }

        it "not allowed" do
          expected_message = '`ssl_truststore_password` not allowed unless `ssl_truststore_path` is configured'
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end
    end
  end
end