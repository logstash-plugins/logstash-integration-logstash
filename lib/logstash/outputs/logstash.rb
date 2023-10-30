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

    if @ssl_enabled == false
      rejected_ssl_settings = @original_params.keys.select { |k| k.start_with?('ssl_') } - %w(ssl_enabled)
      fail(LogStash::ConfigurationError, "Explicit SSL-related settings not supported because `ssl_enabled => false`: #{rejected_ssl_settings}") if rejected_ssl_settings.any?
    end

    # if we don't initialize now, we get runtime error when sending events if there are issues with configs
    @http_client = client
    @load_balancer = LoadBalancer.new(construct_host_uri)

    logger.debug("`logstash` output plugin has been registered.")
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

  def pipeline_shutdown_requested?
    return super if defined?(super) # since LS 8.1.0
    execution_context&.pipeline&.shutdown_requested?
  end

  def abort_batch_if_available!
    raise org.logstash.execution.AbortedBatchException.new if abort_batch_present?
  end

  def abort_batch_present?
    ::Gem::Version.create(LOGSTASH_VERSION) >= ::Gem::Version.create('8.8.0')
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
    end
  end

  def send_events(events)
    body = LogStash::Json.dump(events.map(&:to_hash))
    compressed_body = gzip(body)

    loop do
      url = ""
      begin
        response = @load_balancer.select do |selected_host_uri|
          url = selected_host_uri
          http_client.post(selected_host_uri, :body => compressed_body, :headers => @headers).call
        end

        break if response_success?(response.code)

        retryable_response = retryable_response?(response.code)
        log_response(url, response, events, retryable_response)

        # allow retrying unless pipeline shutdown requested and retriable response
        break unless retryable_response || pipeline_shutdown_requested?
      rescue => exception
        retryable_exception = retryable_exception?(exception)
        log_exception(url, exception, body, retryable_exception)

        # allow retrying unless pipeline shutdown requested and retriable exception
        break unless retryable_exception || pipeline_shutdown_requested?
      end

      if pipeline_shutdown_requested?
        logger.info("Aborting the batch due to shutdown request.")
        abort_batch_if_available!
      end
    end
  rescue => e
    # This should never happen unless there's a flat out bug in the code
    logger.error("Error occurred while sending events",
                 :class => e.class.name,
                 :message => e.message,
                 :backtrace => e.backtrace)
    raise e
  end

  def log_response(uri, response, events, retriable)
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
                   :events => events
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

end