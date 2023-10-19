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
        expect(registered_plugin.send(:construct_host_uri).first.eql?("https://127.0.0.1:9800/")).to be_truthy
      end

      describe "SSL disabled" do
        let(:config) { super().merge("ssl_enabled" => false) }

        it "causes HTTP scheme" do
          expect(registered_plugin.send(:construct_host_uri).first.eql?("http://127.0.0.1:9800/")).to be_truthy
        end
      end

      describe "custom port" do
        let(:config) { super().merge("hosts" => "127.0.0.1:9808") }

        it "will be applied" do
          expect(registered_plugin.send(:construct_host_uri).first.eql?("https://127.0.0.1:9808/")).to be_truthy
        end
      end
    end

    describe "username and password auth" do
      let(:config) { super().merge("hosts" => "my-ls-downstream.com:1234", "ssl_enabled" => false) }

      context "with `username`" do
        let(:config) { super().merge("username" => "test_user") }

        it "requires `password`" do
          expected_message = "User 'test_user' specified without password!"
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

  end

  describe "batch send" do

    it "should successfully send events" do
      allow(registered_plugin.instance_variable_get(:@http_client)).to receive(:send).and_return({ "code" => 200 })
      registered_plugin.multi_receive([event])
      #expect(registered_plugin).to receive(:analyze_response) do |action|
      #  expect(action).to eq(:success)
      #end
    end

    describe "retry with a response codes" do

      it "with internal server error" do

      end

      it "with too many requests error" do

      end
    end

    describe "retry with a exception message" do

      it "with Manticore socket timeout" do
        # ::Manticore::SocketTimeout
      end

      it "with connection reset by peer error" do

      end
    end

    # shutdown requested behaviour

  end
end