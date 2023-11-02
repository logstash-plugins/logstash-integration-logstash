# encoding: utf-8

require "logstash/outputs/base"
require "logstash/namespace"

require 'logstash/plugin_mixins/normalize_config_support'
require "logstash/plugin_mixins/http_client"
require "logstash/plugin_mixins/validator_support/required_host_optional_port_validation_adapter"
require "zlib"

class LogStash::Outputs::Logstash < LogStash::Outputs::Base
  extend LogStash::PluginMixins::ValidatorSupport::RequiredHostOptionalPortValidationAdapter

  include LogStash::PluginMixins::HttpClient[:with_deprecated => false]
  include LogStash::PluginMixins::NormalizeConfigSupport

  require "logstash/utils/load_balancer"

  config_name "logstash"

  # Sets the host of the downstream Logstash instance.
  # Host can be any of IPv4, IPv6 (requires to be in enclosed bracket) or host name, the forms:
  #     `"127.0.0.1"` or `["127.0.0.1"]` if single host with default port
  #     `"127.0.0.1:9801"` or `["127.0.0.1:9801"]` if single host with custom port
  #     `["foo-bar.com", "foo-bar.com:9800"]`
  #     `["[::1]", "[::1]:9000"]`
  #     `"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]"`
  #
  config :hosts, :validate => :required_host_optional_port, :list => true, :required => true

  config :username, :validate => :string, :required => false

  config :ssl_enabled, :validate => :boolean, :default => true

  config :user, :validate => :string, :deprecated => "Use `username` instead.", :required => false

  DEFAULT_PORT = 9800.freeze

  RETRIABLE_CODES = [429, 500, 502, 503, 504]
  RETRYABLE_MANTICORE_EXCEPTIONS = [
    ::Manticore::Timeout,
    ::Manticore::SocketException,
    ::Manticore::ClientProtocolException,
    ::Manticore::ResolutionFailure,
    ::Manticore::SocketTimeout
  ]
  RETRYABLE_EXCEPTION_PATTERN = Regexp.union([
    /Connection reset by peer/i,
    /Read Timed out/i,
  ])

  # @api private
  attr_reader :http_client

  def initialize(*a)
    super


    if original_params.include?('codec')
      fail LogStash::ConfigurationError, 'The `logstash` output does not have an externally-configurable `codec`'
    end

    @headers = {
      "Content-Type" => "application/x-ndjson".freeze,
      "Content-Encoding" => "gzip".freeze
    }.freeze

    logger.debug("`logstash` output plugin has been initialized.")
  end

  def register
    logger.debug("Registering `logstash` output plugin.")

    @username = normalize_config(:username) do |normalize|
      normalize.with_deprecated_alias(:user)
    end

    validate_auth_settings!

    if @ssl_enabled == false
      rejected_ssl_settings = @original_params.keys.select { |k| k.start_with?('ssl_') } - %w(ssl_enabled)
      fail(LogStash::ConfigurationError, "Explicit SSL-related settings not supported because `ssl_enabled => false`: #{rejected_ssl_settings}") if rejected_ssl_settings.any?
    end

    validate_ssl_identity_options!
    validate_ssl_trust_options!

    # if we don't initialize now, we get runtime error when sending events if there are issues with configs
    @http_client = client
    construct_host_uris = construct_host_uri
    fail(LogStash::ConfigurationError, "Resolved host URIs from the `hosts` are empty and not allowed.") if !construct_host_uris.any? || construct_host_uris.size == 0

    @load_balancer = LoadBalancer.new(construct_host_uris)

    logger.debug("`logstash` output plugin has been registered.")
  end

  def validate_auth_settings!
    if @username
      fail(LogStash::ConfigurationError, '`password` is REQUIRED when `username` is provided.') if @password.nil?
      logger.warn("Transmitting credentials over non-secured connection.") if @ssl_enabled == false
    elsif @password
      fail(LogStash::ConfigurationError, '`password` not allowed unless `username` is configured.')
    end
  end

  def validate_ssl_identity_options!
    if @ssl_certificate && @ssl_keystore_path
      fail(LogStash::ConfigurationError, "SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both.")
    elsif @ssl_certificate
      fail(LogStash::ConfigurationError, "`ssl_key` is REQUIRED when `ssl_certificate` is provided.") if @ssl_key.nil?
    elsif @ssl_key
      fail(LogStash::ConfigurationError, "`ssl_key` is not allowed unless `ssl_certificate` is configured.")
    elsif @ssl_keystore_path
      fail(LogStash::ConfigurationError, "`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is provided.") if @ssl_keystore_password.nil?
    elsif @ssl_keystore_password
      fail(LogStash::ConfigurationError, "`ssl_keystore_password` is not allowed unless `ssl_keystore_path` is configured.")
    else
      # acceptable
    end
  end

  def validate_ssl_trust_options!
    if @ssl_certificate_authorities&.any? && @ssl_truststore_path
      fail(LogStash::ConfigurationError, "SSL trust can be configured with EITHER `ssl_certificate_authorities` OR `ssl_truststore_*`, but not both.")
    elsif @ssl_certificate_authorities&.any?
      fail(LogStash::ConfigurationError, "SSL Certificate Authorities cannot be configured when `ssl_verification_mode => none`.") if @ssl_verification_mode == 'none'
    elsif @ssl_truststore_path
      fail(LogStash::ConfigurationError, "SSL Truststore cannot be configured when `ssl_verification_mode => none`.") if @ssl_verification_mode == 'none'
      fail(LogStash::ConfigurationError, "`ssl_truststore_password` is REQUIRED when `ssl_truststore_path` is provided.") if @ssl_truststore_password.nil?

    elsif @ssl_truststore_password
      fail(LogStash::ConfigurationError, "`ssl_truststore_password` not allowed unless `ssl_truststore_path` is configured.")
    end
  end

  def multi_receive(events)
    return if events.empty?

    send_events(events)
  end

  def stop
    logger.debug("`logstash` output plugin has been stopped.")
  end

  def close
    logger.debug("Closing `logstash` output plugin.")
    http_client.close
    logger.debug("`logstash` output plugin has been closed.")
  end

  private

  def construct_host_uri
    scheme = @ssl_enabled ? 'https'.freeze : 'http'.freeze
    @hosts.map do |destination| # Struct(:host,:port)
      URI::Generic.build(:scheme => scheme,
                         :host   => destination.host,
                         :port   => destination.port || DEFAULT_PORT)
    end.map(&:to_s).map(&:freeze)
  end

  def send_events(events)
    body = LogStash::Json.dump(events.map(&:to_hash))
    compressed_body = gzip(body)

    loop do
      next_action = transmit(body, compressed_body)
      break unless next_action == :retry
    end
  rescue => e
    # This should never happen unless there's a flat out bug in the code
    logger.error("Error occurred while sending events",
                 :class => e.class.name,
                 :message => e.message,
                 :backtrace => e.backtrace)
    raise e
  end

  ##
  # @param body [String]
  # @param compressed_body [String]
  # @return [:done, :abort, :retry]
  def transmit(body, compressed_body)
    url = nil
    response = @load_balancer.select do | selected_host_uri |
      url = selected_host_uri
      http_client.post(selected_host_uri, :body => compressed_body, :headers => @headers).call
    end

    return :done if response_success?(response.code)

    retryable_response = retryable_response?(response.code)
    log_response(url, response, body, retryable_response)

    return retryable_response ? :retry : :abort
  rescue => exception
    retryable_exception = retryable_exception?(exception)
    log_exception(url, exception, body, retryable_exception)

    return retryable_exception ? :retry : :abort
  end

  def log_response(uri, response, body, retriable)
    response_code = response.code
    if retriable
      if response_code == 429
        logger.debug("Encountered a retriable 429 response")
      else
        logger.warn("Encountered a retryable error in `logstash` output", :code => response_code, :body => response.body)
      end
    else
      logger.error("Encountered error",
                   :response_code => response_code,
                   :host => uri,
                   :body => body
      )
    end
  end

  def log_exception(uri, exception, body, retriable)
    log_entry = { :host => uri, :message => exception.message, :class => exception.class, :retry => retriable }
    if logger.debug?
      # backtraces are big
      log_entry[:backtrace] = exception.backtrace
      # body can be big and may have sensitive data
      log_entry[:body] = body
    end
    logger.error("Could not send data to host", log_entry)
  end

  def gzip(data)
    gz = StringIO.new
    gz.set_encoding("BINARY")
    z = Zlib::GzipWriter.new(gz)
    z.write(data)
    z.close
    gz.string
  end

  def response_success?(response_code)
    response_code >= 200 && response_code <= 299
  end

  def retryable_exception?(exception)
    retryable_manticore_exception?(exception) || retryable_unknown_exception?(exception)
  end

  def retryable_manticore_exception?(exception)
    RETRYABLE_MANTICORE_EXCEPTIONS.any? {|me| exception.is_a?(me)}
  end

  def retryable_unknown_exception?(exception)
    exception.is_a?(::Manticore::UnknownException) &&
      RETRYABLE_EXCEPTION_PATTERN.match?(exception.message)
  end

  def retryable_response?(response_code)
    RETRIABLE_CODES.include?(response_code)
  end

  # Emulate `pipeline_shutdown_requested?` when running on older Logstash
  unless ::Gem::Version.create(LOGSTASH_VERSION) >= ::Gem::Version.create('8.1.0')
    def pipeline_shutdown_requested?
      execution_context&.pipeline&.shutdown_requested?
    end
  end

  # When running on Logstash that can abort batches,
  # raise the required exception, do nothing otherwise.
  if ::Gem::Version.create(LOGSTASH_VERSION) >= ::Gem::Version.create('8.8.0')
    def abort_batch_if_available!
      raise org.logstash.execution.AbortedBatchException.new
    end
  else
    def abort_batch_if_available!
      nil
    end
  end
end