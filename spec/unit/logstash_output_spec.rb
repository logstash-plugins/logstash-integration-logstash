# encoding: utf-8

require_relative "../spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/outputs/logstash"

describe LogStash::Outputs::Logstash do

  let(:config) {{ "hosts" => "127.0.0.1" }}

  subject(:plugin) { LogStash::Outputs::Logstash.new(config) }
  let(:registered_plugin) { plugin.tap(&:register) }

  let(:event) {
    LogStash::Event.new({"message" => "Sending my hello to upstream input"})
  }

  describe "a plugin class" do
    subject { described_class }

    it { is_expected.to be_a_kind_of Class }
    it { is_expected.to be <= LogStash::Outputs::Base }
    it { is_expected.to have_attributes(:config_name => "logstash") }
    it { is_expected.to have_attributes(:concurrency => :shared) }
  end

  describe "a plugin instance with minimal config" do
    subject(:instance) { described_class.new(config) }

    it { is_expected.to respond_to(:register).with(0).arguments }
    it { is_expected.to respond_to(:multi_receive).with(1).argument }
    it { is_expected.to respond_to(:stop).with(0).arguments }
    it { is_expected.to respond_to(:close).with(0).arguments }
  end

  describe "plugin register" do

    describe "construct host URI" do

      it "applies default https scheme and 9800 port" do
        normalized_hosts = registered_plugin.send(:normalize_host_uris)
        expect(normalized_hosts).to have_attributes(:size => 1)
        expect(normalized_hosts.first).to eql("https://127.0.0.1:9800")
      end

      describe "SSL disabled" do
        let(:config) { super().merge("ssl_enabled" => false) }

        it "causes HTTP scheme" do
          normalized_hosts = registered_plugin.send(:normalize_host_uris)
          expect(normalized_hosts).to have_attributes(:size => 1)
          expect(normalized_hosts.first).to eql("http://127.0.0.1:9800")
        end
      end

      describe "custom port" do
        let(:config) { super().merge("hosts" => "127.0.0.1:9808") }

        it "will be applied" do
          normalized_hosts = registered_plugin.send(:normalize_host_uris)
          expect(normalized_hosts).to have_attributes(:size => 1)
          expect(normalized_hosts.first).to eql("https://127.0.0.1:9808")
        end
      end
    end

    describe "username and password auth" do
      let(:config) { super().merge("hosts" => "my-ls-downstream.com:1234", "ssl_enabled" => false) }

      context "with `username`" do
        let(:config) { super().merge("username" => "test_user") }

        it "requires `password`" do
          expected_message = "`password` is REQUIRED when `username` is provided"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
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
          expected_message = "`ssl_key` is REQUIRED when `ssl_certificate` is provided"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end

        context "with keystore" do
          let(:config) { super().merge("ssl_keystore_path" => cert_fixture!("client_from_root.jks"), "ssl_key" => cert_fixture!("server_from_root.key.pem")) }

          it "cannot be used together" do
            expected_message = "SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both"
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
          expected_message = "`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is provided"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end

      context "`ssl_keystore_password`" do
        let(:config) { super().merge("ssl_keystore_password" => "pa$$w0rd") }

        it "requires `ssl_keystore_path`" do
          expected_message = "`ssl_keystore_password` is not allowed unless `ssl_keystore_path` is configured"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end
    end

    context "trust" do
      let(:config) { super().merge("ssl_enabled" => true) }

      context "with CA" do
        let(:config) { super().merge("ssl_certificate_authorities" => cert_fixture!("root.pem")) }

        context "and `ssl_verification_mode` is 'none'" do
          let(:config) { super().merge("ssl_verification_mode" => "none") }

          it "not allowed" do
            expected_message = "SSL Certificate Authorities cannot be configured when `ssl_verification_mode => none`"
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end

        context "and truststore" do
          let(:config) { super().merge("ssl_truststore_path" => cert_fixture!("client_self_signed.jks")) }

          it "not allowed" do
            expected_message = "SSL trust can be configured with EITHER `ssl_certificate_authorities` OR `ssl_truststore_*`, but not both"
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end
      end

      context "truststore" do
        let(:config) { super().merge("ssl_truststore_path" => cert_fixture!('client_self_signed.jks')) }

        it "requires truststore password" do
          expected_message = "`ssl_truststore_password` is REQUIRED when `ssl_truststore_path` is provided"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end

        context "and `ssl_verification_mode` is 'none'" do
          let(:config) { super().merge("ssl_verification_mode" => "none") }

          it "not allowed" do
            expected_message = "SSL Truststore cannot be configured when `ssl_verification_mode => none`"
            expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
          end
        end
      end

      context "password without truststore path" do
        let(:config) { super().merge("ssl_truststore_password" => "pa$$w0rd") }

        it "not allowed" do
          expected_message = "`ssl_truststore_password` not allowed unless `ssl_truststore_path` is configured"
          expect{ registered_plugin }.to raise_error(LogStash::ConfigurationError).with_message(expected_message)
        end
      end
    end
  end

  describe "#transmit" do
    let(:normalized_host_uri) { "https://127.0.0.1:9800" }

    let(:encoded_body) { "[]" }
    let(:compressed_body) { "\x1F\xC3\xA3\b\x00\xE2\x80\xBA\xE2\x80\x9ACe\x00\x03\xC3\xA3\xC3\xA9\xC3\x82\x02\x00D\xE2\x80\x9Chp\x03\x00\x00\x00".b }

    subject(:transmit_result) { registered_plugin.send(:transmit, encoded_body, compressed_body) }

    context "successful transmission" do
      before(:each) do
        registered_plugin.http_client.stub(normalized_host_uri, body: "Response body", code: 200)
      end
      it "returns :done" do
        expect(transmit_result).to eql :done
      end
    end

    context "retriable HTTP errors" do
      [429, 500].each do |retriable_response_code|
        context "when http client emits #{retriable_response_code} retriable error response" do
          before(:each) do
            registered_plugin.http_client.stub(normalized_host_uri, body: "Response body", code: retriable_response_code)
          end
          it 'returns :retry' do
            expect(transmit_result).to eql :retry
          end
        end
      end
    end

    context "terminal HTTP errors" do
      [301, 400, 404].each do |terminal_response_code|
        context "when http client emits #{terminal_response_code} terminal error response" do
          before(:each) do
            registered_plugin.http_client.stub(normalized_host_uri, body: "Response body", code: terminal_response_code)
          end
          it 'returns :abort' do
            expect(transmit_result).to eql :abort
          end
        end
      end
    end

    context "retriable transmission exceptions" do
      [
        Manticore::Timeout.new,
        Manticore::SocketException.new,
        Manticore::ClientProtocolException.new,
        Manticore::ResolutionFailure.new,
        Manticore::SocketTimeout.new,
        Manticore::UnknownException.new("Connection reset by peer"),
        Manticore::UnknownException.new("Read Timed out"),
      ].each do |manticore_exception|
        context "when http client raises retriable exception `#{manticore_exception}`" do
          before(:each) do
            expect(registered_plugin.http_client).to receive(:post).and_raise(manticore_exception)
          end
          it "returns :retry" do
            expect(transmit_result).to eql :retry
          end
        end
      end
    end
  end

  describe '#multi_receive' do
    let(:events) { [event] }

    context "when first transmit succeeds" do
      before(:each) do
        allow(registered_plugin).to receive(:transmit).and_return(:abort).once
      end
      it "transmits once" do
        registered_plugin.multi_receive(events)
        expect(registered_plugin).to have_received(:transmit).once
      end
    end

    context "when first transmit gets terminal failure" do
      before(:each) do
        allow(registered_plugin).to receive(:transmit).and_return(:abort).once
      end
      it "transmits once" do
        registered_plugin.multi_receive(events)
        expect(registered_plugin).to have_received(:transmit).once
      end
    end

    context "when transmit indicates that a retry is required" do
      # Configure a _sequence_ of `#transmit` responses
      # emits :retry `retry_count` times, invoking `limit_met_hook` (if present) before the
      # LAST normal retry, then emits `limit_met_next_action`.
      # as a safeguard, this mock can be called AT MOST `retry_count + 1` times
      let(:retry_count) { 3 }
      let(:limit_met_hook) { nil }
      let(:limit_met_next_action) { :retry }
      before(:each) do
        attempts_made = 0
        next_action = :retry
        allow(registered_plugin).to receive(:transmit).with(any_args) do
          current_action = next_action
          attempts_made += 1
          if attempts_made == retry_count
            limit_met_hook&.call
            next_action = limit_met_next_action
          end
          current_action
        end.at_most(retry_count + 1).times
      end

      context "and transmit eventually succeeds" do
        let(:limit_met_next_action) { :done }
        it "stops retrying" do
          registered_plugin.multi_receive(events)

          expect(registered_plugin).to have_received(:transmit).exactly(retry_count + 1).times
        end
      end

      context "and transmit eventually gets terminal failure" do
        let(:limit_met_next_action) { :abort }
        it "stops retrying" do
          registered_plugin.multi_receive(events)

          expect(registered_plugin).to have_received(:transmit).exactly(retry_count + 1).times
        end
      end

      context "and the pipeline shutdown is requested before transmission succeeds" do
        let(:limit_met_hook) do
          ->() { expect(registered_plugin).to receive(:pipeline_shutdown_requested?).and_return(:true) }
        end
        let(:limit_met_next_action) { :retry }

        if ::Gem::Version.create(LOGSTASH_VERSION) >= ::Gem::Version.create('8.8.0')
          it 'aborts the batch' do
            expect { registered_plugin.multi_receive(events) }.to raise_exception(org.logstash.execution.AbortedBatchException)

            expect(registered_plugin).to have_received(:transmit).exactly(retry_count).times
          end
        else
          it "stops retrying" do
            registered_plugin.multi_receive(events)

            expect(registered_plugin).to have_received(:transmit).exactly(retry_count).times
          end
        end
      end
    end
  end
end