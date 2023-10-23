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
    let(:client) { double("Manticore client") }
    let(:response) { double("response object") }

    it "successfully sends events" do
      allow(registered_plugin.instance_variable_get(:@http_client)).to receive(:send).and_return(client)
      allow(client).to receive(:call).and_return(response)
      allow(response).to receive(:code).and_return(200)
      expect(registered_plugin).to receive(:analyze_response).with(any_args).and_return(:success)

      registered_plugin.multi_receive([event])
    end

    describe "with a response codes" do

      before do
        allow(registered_plugin.instance_variable_get(:@http_client)).to receive(:send).and_return(client)
        allow(client).to receive(:call).and_return(response)
      end

      it "retries on retriable server errors" do
        # initial return code is either 429 or 500 and then 200 to stop the while retry loop
        allow(response).to receive(:code).and_return([429, 500].sample, 200)
        allow(response).to receive(:body).and_return("Retriable error.", "Send succeeded.")
        expect(registered_plugin).to receive(:analyze_response).exactly(2).and_call_original
        expect(registered_plugin).to receive(:analyze_exception).never

        registered_plugin.multi_receive([event])
      end

      it "doesn't retry on other non-retriable errors" do
        # initial return code is either 400 or 404 and then 200 to stop the while retry loop
        allow(response).to receive(:code).and_return([400, 404].sample)
        allow(response).to receive(:body).and_return("Non-retriable error.", "Send succeeded.")
        expect(registered_plugin).to receive(:analyze_response).exactly(1).and_call_original
        expect(registered_plugin).to receive(:analyze_exception).never

        registered_plugin.multi_receive([event])

      end
    end

    describe "with an exception message" do
      let(:config) { super().merge("hosts" => %w[127.0.0.1 my-ls-downstream.com:1234]) }
      let(:exception_raising_client) { double("Exceptional Manticore client") }

      before do
        # a simulation, where 127.0.0.1 host raises an exception and retry to my-ls-downstream.com will be succeeded
        allow(registered_plugin.instance_variable_get(:@http_client)).to receive(:send) do | _, url, _, _|
          url.eql?("https://127.0.0.1:9800/") ? exception_raising_client : client
        end
      end

      it "with Manticore socket timeout" do
        allow(exception_raising_client).to receive(:call).and_raise(Manticore::SocketTimeout.new)
        allow(client).to receive(:call).and_return(response)
        allow(response).to receive(:code).and_return(200)
        expect(registered_plugin).to receive(:analyze_response).exactly(1).and_call_original # catches the success
        expect(registered_plugin).to receive(:analyze_exception).exactly(1).and_call_original

        registered_plugin.multi_receive([event])
      end

      it "with connection reset by peer error" do
        allow(exception_raising_client).to receive(:call).and_raise(Manticore::UnknownException.new "Connection reset by peer")
        allow(client).to receive(:call).and_return(response)
        allow(response).to receive(:code).and_return(200)
        expect(registered_plugin).to receive(:analyze_response).exactly(1).and_call_original # catches the success
        expect(registered_plugin).to receive(:analyze_exception).exactly(1).and_call_original

        registered_plugin.multi_receive([event])
      end
    end
  end
end