# encoding: utf-8

require 'logstash/inputs/base'
require 'logstash/namespace'

require "logstash/plugin_mixins/plugin_factory_support"

require 'logstash/codecs/json_lines'

class LogStash::Inputs::Logstash < LogStash::Inputs::Base
  include LogStash::PluginMixins::PluginFactorySupport

  config_name "logstash"

  config :host,     :validate => :string,   :default => "0.0.0.0"
  config :port,     :validate => :number,   :default => 9800

  # optional username/password credentials
  config :username, :validate => :string,   :required => false
  config :password, :validate => :password, :required => false

  config :ssl_enabled, :validate => :boolean, :default => true

  # SSL:IDENTITY:SOURCE cert/key pair
  config :ssl_certificate,    :validate => :path
  config :ssl_key,            :validate => :path
  config :ssl_key_passphrase, :validate => :password

  # SSL:IDENTITY:SOURCE keystore
  config :ssl_keystore_path,     :validate => :path
  config :ssl_keystore_password, :validate => :password

  # SSL:TRUST:CONFIG
  config :ssl_client_authentication,   :validate => %w(none optional required), :default => 'none'

  # SSL:TRUST:SOURCE ca file
  config :ssl_certificate_authorities, :validate => :path, :list => true

  # SSL:TUNING
  config :ssl_handshake_timeout, :validate => :number, default: 10_000
  config :ssl_cipher_suites, :validate => :string, :list => true
  config :ssl_supported_protocols, :validate => :string, :list => true

  def initialize(*a)
    super

    if original_params.include?('codec')
      report_invalid_config! 'The `logstash` input does not have an externally-configurable `codec`'
    end

    logger.debug("initializing inner HTTP input plugin")
    @internal_http = plugin_factory.input('http').new(inner_http_input_options)
    logger.debug("inner HTTP input plugin has been initialized")
  end

  def register
    logger.debug("registering inner HTTP input plugin")
    @internal_http.register
    logger.debug("inner HTTP input plugin has been registered")
  end

  def run(queue)
    logger.debug("starting inner HTTP input plugin")
    @internal_http.run(QueueWrapper.new(queue, method(:decorate)))
    logger.debug("inner HTTP input plugin has exited normally")
  rescue => e
    logger.error("inner HTTP plugin has had an unrecoverable exception: #{e.message} at #{e.backtrace.first}")
    raise
  end

  def stop
    logger.debug("stopping inner HTTP input plugin")
    @internal_http.stop
    logger.debug('inner HTTP plugin has been stopped')
  end

  def close
    logger.debug("closing inner HTTP input plugin")
    @internal_http.close
    logger.debug('inner HTTP plugin has been closed')
  end

  def inner_http_input_options
    @_inner_http_input_options ||= begin
      http_options = {
        # directly-configurable
        'host' => @host,
        'port' => @port,

        # non-configurable codec
        'codec' => plugin_factory.codec('json_lines').new(inner_json_lines_codec_options),
        'additional_codecs' => {},
        'response_headers' => { 'Accept' => 'application/x-ndjson' },

        # enrichment avoidance
        'ecs_compatibility'            => 'disabled',
        'remote_host_target_field'     => '[@metadata][void]',
        'request_headers_target_field' => '[@metadata][void]',
      }

      if @username
        http_options['user'] = @username
        http_options['password'] = @password || report_invalid_config!('`password` is REQUIRED when `username` is provided')
        logger.warn("transmitting credentials over non-secured connection") if @ssl_enabled == false
      elsif @password
        report_invalid_config!('`password` not allowed unless `username` is configured')
      end

      if @ssl_enabled == false
        rejected_ssl_settings = @original_params.keys.select { |k| k.start_with?('ssl_') } - %w(ssl_enabled)
        report_invalid_config!("Explicit SSL-related settings not supported because `ssl_enabled => false`: #{rejected_ssl_settings}") if rejected_ssl_settings.any?
      else
        http_options['ssl_enabled'] = true

        http_options['ssl_cipher_suites'] = @ssl_cipher_suites if @original_params.include?('ssl_cipher_suites')
        http_options['ssl_supported_protocols'] = @ssl_supported_protocols if @original_params.include?('ssl_supported_protocols')
        http_options['ssl_handshake_timeout'] = @ssl_handshake_timeout

        http_options.merge!(ssl_identity_options)
        http_options.merge!(ssl_trust_options)
      end

      http_options
    end
  end

  def ssl_identity_options
    {}.tap do |identity_options|
      if @ssl_certificate && @ssl_keystore_path
        report_invalid_config!('SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both')
      elsif @ssl_certificate
        identity_options['ssl_certificate'] = @ssl_certificate
        identity_options['ssl_key'] = @ssl_key || report_invalid_config!('`ssl_key` is required when `ssl_certificate` is configured')
        identity_options['ssl_key_passphrase'] = @ssl_key_passphrase unless @ssl_key_passphrase.nil?
      elsif @ssl_key
        report_invalid_config!('`ssl_key` is not allowed unless `ssl_certificate` is configured')
      elsif @ssl_key_passphrase
        report_invalid_config!('`ssl_key_passphrase` is not allowed unless `ssl_key` is configured')
      elsif @ssl_keystore_path
        identity_options['ssl_keystore_path'] = @ssl_keystore_path
        identity_options['ssl_keystore_password'] = @ssl_keystore_password || report_invalid_config!('`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is configured')
      elsif @ssl_keystore_password
        report_invalid_config!('`ssl_keystore_password` is not allowed unless `ssl_keystore_path` is configured')
      else
        report_invalid_config!('SSL identity MUST be configured with either `ssl_certificate`/`ssl_key` or `ssl_keystore_*`')
      end
    end
  end

  def ssl_trust_options
    {
      'ssl_client_authentication' => @ssl_client_authentication,
    }.tap do |trust_options|
      if @ssl_certificate_authorities&.any?
        if @ssl_client_authentication == 'none'
          report_invalid_config!('`ssl_certificate_authorities` is not supported because `ssl_client_authentication => none`')
        end

        trust_options['ssl_certificate_authorities'] = @ssl_certificate_authorities
      end
    end
  end

  def inner_json_lines_codec_options
    @_inner_json_lines_codec_options ||= {
      # enrichment avoidance
      'ecs_compatibility' => 'disabled',
    }
  end

  def report_invalid_config!(message)
    fail(LogStash::ConfigurationError, message)
  end

  class QueueWrapper
    def initialize(wrapped_queue, decorator)
      @wrapped_queue = wrapped_queue
      @decorator = decorator
    end

    def << (event)
      event.remove('[@metadata][void]')
      @decorator.call(event)
      @wrapped_queue << event
    end
  end
end