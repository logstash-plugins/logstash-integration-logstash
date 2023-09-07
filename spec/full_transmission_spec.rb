# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"

require "logstash/inputs/logstash"
require "logstash/outputs/logstash"

require 'rspec/collection_matchers'

require 'random-port'

describe 'Logstash Output -> Input complete transmission' do

  def cert_fixture(name)
    File.expand_path("fixtures/certs/generated/#{name}", __dir__)
  end

  def cert_fixture!(name)
    cert_fixture(name).tap do |filename|
      fail "MISSING: #{filename}" unless File.file?(filename)
      fail "UNREADABLE: #{filename}" unless File.readable?(filename)
    end
  end

  let(:port) { @available_port }

  around(:each) do |example|
    RandomPort::Pool::SINGLETON.acquire do |available_port|
      @available_port = available_port
      example.call
    end
  end

  # requires: input_events (an array of Events)
  # requires: output_plugin (a Logstash output plugin)
  # requires: input_plugin (a Logstash input plugin)
  # optional: concurrency (default: 1)
  # optional: batch_size (default: 125)
  # provides: output_events (an array of Events)
  shared_context 'transmission' do
    let(:concurrency) { defined?(super) ? super() : 8 }
    let(:batch_size) { defined?(super) ? super() : 125 }

    let(:output_events) { [] }
    let(:errors) { [] }

    before(:each) do
      input_plugin.register
      output_plugin.register

      transmit_queue = Queue.new
      input_events.each_slice(batch_size) { |batch| transmit_queue << batch }

      receipt_queue = Queue.new
      input_thread = Thread.new(receipt_queue) { |queue| input_plugin.run(queue) }

      error_queue = Queue.new

      concurrency.times.map do
        Thread.new(receipt_queue) do
          loop do
            batch = transmit_queue.pop(true) rescue break
            begin
              Timeout.timeout(5) do
                output_plugin.multi_receive(batch)
              end
            rescue => e
              error_queue << e
            end
          end
        end
      end.map(&:join)

      output_plugin.close
      input_plugin.stop
      input_thread.join

      receipt_queue.size.times { output_events << receipt_queue.pop }
      error_queue.size.times { errors << error_queue.pop }
    end
  end

  # provides: input_events
  # depends: output_events
  shared_examples "large sequence" do
    let(:event_count) { 10_000 }

    let(:input_events) { (0...event_count).map { |idx| LogStash::Event.new("event" => {"sequence" => idx}) } }

    it 'transmits all events' do
      expect(output_events).to have_exactly(event_count).items

      expect(output_events.map{|e| e.get("[event][sequence]")}.uniq).to have_exactly(event_count).items
    end
  end

  shared_examples "connection failure" do
    let(:input_events) { [LogStash::Event.new("event" => {"sequence" => 999})] }

    it 'fails to transmit the events' do
      expect(errors).to have_exactly(1).items
      expect(output_events).to be_empty
    end
  end

  context 'basic plaintext' do
    let(:output_plugin) { LogStash::Outputs::Logstash.new("host" => "127.0.0.1", "port" => port, "ssl_enabled" => false) }
    let(:input_plugin) { LogStash::Inputs::Logstash.new("host" => "127.0.0.1", "port" => port, "ssl_enabled" => false) }

    include_context 'transmission'
    include_examples "large sequence"
  end

  context 'simple ssl with client authentication none' do
    let(:input_plugin) {
      LogStash::Inputs::Logstash.new({
          "host" => "127.0.0.1", "port" => port,
          "ssl_keystore_path" => cert_fixture!('server_from_root.jks'),
          "ssl_keystore_password" => "12345678",
        })
    }

    context 'output connects via ssl' do
      let(:output_plugin) {
        LogStash::Outputs::Logstash.new({
            "host" => "127.0.0.1", "port" => port,
            "ssl_certificate_authorities" => cert_fixture!('root.pem'),
          })
      }

      include_context 'transmission'
      include_examples "large sequence"
    end

    context 'output connects without ssl' do
      let(:output_plugin) {
        LogStash::Outputs::Logstash.new({
            "host" => "127.0.0.1", "port" => port,
            "ssl_enabled" => false,
          })
      }

      include_context 'transmission'
      include_examples "connection failure"
    end

  end

  context 'client auth ssl' do
    let(:input_plugin) {
      LogStash::Inputs::Logstash.new({
          "host" => "127.0.0.1", "port" => port,
          "ssl_certificate" => cert_fixture!('server_from_root.pem'),
          "ssl_key" => cert_fixture!('server_from_root.key.pkcs8.pem'),
          "ssl_key_passphrase" => "12345678",
          "ssl_certificate_authorities" => cert_fixture!('root.pem'),
          "ssl_client_authentication" => "required",
        })
    }

    context 'output presents peer certificate' do
      let(:output_plugin) {
        LogStash::Outputs::Logstash.new({
            "host" => "127.0.0.1", "port" => port,
            "ssl_certificate_authorities" => cert_fixture!('root.pem'),
            "ssl_keystore_path" => cert_fixture!('client_from_root.jks'),
            "ssl_keystore_password" => "12345678",
          })
      }

      include_context 'transmission'
      include_examples "large sequence"
    end

    context 'output presents NO certificate' do
      let(:output_plugin) {
        LogStash::Outputs::Logstash.new({
            "host" => "127.0.0.1", "port" => port,
            "ssl_certificate_authorities" => cert_fixture!('root.pem'),
          })
      }

      include_context 'transmission'
      include_examples "connection failure"
    end



    context 'output presents untrusted certificate' do
      let(:output_plugin) {
        LogStash::Outputs::Logstash.new({
            "host" => "127.0.0.1", "port" => port,
            "ssl_certificate_authorities" => cert_fixture!('root.pem'),
            "ssl_keystore_path" => cert_fixture!('client_from_untrusted.jks'),
            "ssl_keystore_password" => "12345678",
          })
      }

      include_context 'transmission'
      include_examples "connection failure"
    end

    context 'output presents self-signed certificate' do
      let(:output_plugin) {
        LogStash::Outputs::Logstash.new({
            "host" => "127.0.0.1", "port" => port,
            "ssl_certificate_authorities" => cert_fixture!('root.pem'),
            "ssl_keystore_path" => cert_fixture!('client_self_signed.jks'),
            "ssl_keystore_password" => "12345678",
          })
      }

      include_context 'transmission'
      include_examples "connection failure"
    end
  end
end