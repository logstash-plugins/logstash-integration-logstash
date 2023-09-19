# encoding: utf-8

require 'logstash/outputs/base'
require 'logstash/namespace'

require "logstash/plugin_mixins/plugin_factory_support"

class LogStash::Outputs::Logstash < LogStash::Outputs::Base
  include LogStash::PluginMixins::PluginFactorySupport

  config_name "logstash"

  config :host,     :validate => :string,   :required => true
  config :port,     :validate => :number,   :required => true

  # optional username/password credentials
  config :username, :validate => :string,   :required => false
  config :password, :validate => :password, :required => false

  config :ssl_enabled,                 :validate => :boolean, :default => true

  # SSL:IDENTITY:SOURCE cert/key pair
  config :ssl_certificate,             :validate => :path
  config :ssl_key,                     :validate => :path

  # SSL:IDENTITY:SOURCE keystore
  config :ssl_keystore_path,           :validate => :path
  config :ssl_keystore_password,       :validate => :password

  # SSL:TRUST:CONFIG
  config :ssl_verification_mode,       :validate => %w(full none), :default => 'full'

  # SSL:TRUST:SOURCE ca file
  config :ssl_certificate_authorities, :validate => :path,         :list => true

  # SSL:TRUST:SOURCE truststore
  config :ssl_truststore_path,         :validate => :path
  config :ssl_truststore_password,     :validate => :password

  # SSL:TUNING
  config :ssl_supported_protocols, :validate => :string, :list => true

  def initialize(*a)
    super

    if original_params.include?('codec')
      fail LogStash::ConfigurationError, 'The `logstash` output does not have an externally-configurable `codec`'
    end

    if @ssl_certificate_authorities && @ssl_certificate_authorities.size > 1
      fail LogStash::ConfigurationError, 'The `logstash` output supports at most one `ssl_certificate_authorities` path'
    end

    logger.debug("initializing inner HTTP output plugin")
    @internal_http = plugin_factory.output('http').new(inner_http_output_options)
    logger.debug("inner HTTP output plugin has been initialized")
  end

  def register
    logger.debug("registering inner HTTP output plugin")
    @internal_http.register
    logger.debug("inner HTTP output plugin has been registered")
  end

  def multi_receive(events)
    return if events.empty?
    logger.trace("proxying #{events.size} events to inner HTTP plugin")
    @internal_http.multi_receive(events)
  rescue => e
    logger.error("inner HTTP plugin has had an unrecoverable exception: #{e.message} at #{e.backtrace.first}")
    raise
  end

  def stop
    logger.debug("stopping inner HTTP output plugin")
    @internal_http.stop
    logger.debug('inner HTTP output plugin has been stopped')
  end

  def close
    logger.debug("closing inner HTTP output plugin")
    @internal_http.close
    logger.debug('inner HTTP output plugin has been closed')
  end

  def inner_http_output_options
    @_inner_http_output_options ||= begin
      http_options = {
        'url' => "#{@ssl_enabled ? 'https' : 'http'}://#{@host}:#{@port}",
        'http_method'          => 'post',
        'retry_non_idempotent' => 'true',

        # non-configurable codec
        'content_type' => 'application/x-ndjson',
        'format'       => 'json_batch',
      }

      if @username
        http_options['user'] = @username
        http_options['password'] = @password || fail(LogStash::ConfigurationError, '`password` is REQUIRED when `username` is provided')
        logger.warn("transmitting credentials over non-secured connection") if @ssl_enabled == false
      elsif @password
        fail(LogStash::ConfigurationError, '`password` not allowed unless `username` is configured')
      end

      if @ssl_enabled == false
        rejected_ssl_settings = @original_params.keys.select { |k| k.start_with?('ssl_') } - %w(ssl_enabled)
        fail(LogStash::ConfigurationError, "Explicit SSL-related settings not supported because `ssl_enabled => false`: #{rejected_ssl_settings}") if rejected_ssl_settings.any?
      else
        http_options['ssl_supported_protocols'] = @ssl_supported_protocols if @original_params.include?('ssl_supported_protocols')

        http_options.merge!(ssl_identity_options)
        http_options.merge!(ssl_trust_options)
      end

      http_options
    end
  end

  def ssl_identity_options
    if @ssl_certificate && @ssl_keystore_path
      fail(LogStash::ConfigurationError, 'SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both')
    elsif @ssl_certificate
      return {
        'ssl_certificate' => @ssl_certificate,
        'ssl_key'  => @ssl_key || fail(LogStash::ConfigurationError, "`ssl_key` is REQUIRED when `ssl_certificate` is provided"),
      }
    elsif @ssl_key
      fail(LogStash::ConfigurationError, '`ssl_key` is not allowed unless `ssl_certificate` is configured')
    elsif @ssl_keystore_path
      return {
        'ssl_keystore_path' => @ssl_keystore_path,
        'ssl_keystore_password' => @ssl_keystore_password || fail(LogStash::ConfigurationError, "`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is provided"),
      }
    elsif @ssl_keystore_password
      fail(LogStash::ConfigurationError, "`ssl_keystore_password` is not allowed unless `ssl_keystore_path` is configured")
    else
      return {}
    end
  end

  def ssl_trust_options
    {
      'ssl_verification_mode' => @ssl_verification_mode,
    }.tap do |trust_options|
      if @ssl_certificate_authorities&.any? && @ssl_truststore_path
        fail(LogStash::ConfigurationError, 'SSL trust can be configured with EITHER `ssl_certificate_authorities` OR `ssl_truststore_*`, but not both')
      elsif @ssl_certificate_authorities&.any?
        fail(LogStash::ConfigurationError, 'SSL Certificate Authorities cannot be configured when `ssl_verification_mode => none`') if @ssl_verification_mode == 'none'

        trust_options['ssl_certificate_authorities'] = @ssl_certificate_authorities.first
      elsif @ssl_truststore_path
        fail(LogStash::ConfigurationError, 'SSL Truststore cannot be configured when `ssl_verification_mode => none`') if @ssl_verification_mode == 'none'

        trust_options['ssl_truststore_path'] = @ssl_truststore_path
        trust_options['ssl_truststore_password'] = @ssl_truststore_password || fail(LogStash::ConfigurationError, '`ssl_truststore_password` is REQUIRED when `ssl_truststore_path` is provided')
      elsif @ssl_truststore_password
        fail(LogStash::ConfigurationError, '`ssl_truststore_password` not allowed unless `ssl_truststore_path` is configured')
      end
    end
  end
end