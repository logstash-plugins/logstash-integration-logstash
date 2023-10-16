# encoding: utf-8

require "logstash/outputs/base"
require "logstash/namespace"

require "logstash/plugin_mixins/http_client"
require "logstash/plugin_mixins/validator_support/required_host_optional_port_validation_adapter"
require "zlib"

class LogStash::Outputs::Logstash < LogStash::Outputs::Base
  extend LogStash::PluginMixins::ValidatorSupport::RequiredHostOptionalPortValidationAdapter

  include LogStash::PluginMixins::HttpClient[:with_deprecated => true]

  require "logstash/outputs/router"

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
  config :ssl_certificate_authorities, :validate => :path, :list => true

  # SSL:TRUST:SOURCE truststore
  config :ssl_truststore_path,         :validate => :path
  config :ssl_truststore_password,     :validate => :password

  # SSL:TUNING
  config :ssl_supported_protocols, :validate => :string, :list => true

  DEFAULT_PORT = 9800.freeze

  HTTP_METHOD = "post".freeze

  RETRIABLE_CODES = [429, 500, 502, 503, 504]
  RETRYABLE_MANTICORE_EXCEPTIONS = [
    ::Manticore::Timeout,
    ::Manticore::SocketException,
    ::Manticore::ClientProtocolException,
    ::Manticore::ResolutionFailure,
    ::Manticore::SocketTimeout
  ]
  RETRYABLE_EXCEPTION_MESSAGES = [
    /Connection reset by peer/i,
    /Read Timed out/i
  ]

  class PluginInternalQueueLeftoverError < StandardError; end

  def initialize(*a)
    super

    if original_params.include?('codec')
      fail LogStash::ConfigurationError, 'The `logstash` output does not have an externally-configurable `codec`'
    end

    if @ssl_certificate_authorities && @ssl_certificate_authorities.size > 1
      fail LogStash::ConfigurationError, 'The `logstash` output supports at most one `ssl_certificate_authorities` path'
    end

    @headers = {}
    @headers["Content-Type"] = "application/x-ndjson"

    logger.debug("`logstash` output plugin has been initialized.")
  end

  def register
    logger.debug("Registering `logstash` output plugin.")

    validate_auth_settings!
    if @ssl_enabled == false
      rejected_ssl_settings = @original_params.keys.select { |k| k.start_with?('ssl_') } - %w(ssl_enabled)
      fail(LogStash::ConfigurationError, "Explicit SSL-related settings not supported because `ssl_enabled => false`: #{rejected_ssl_settings}") if rejected_ssl_settings.any?
    end
    validate_ssl_identity_options!
    validate_ssl_trust_options!

    @router = Router.new(construct_host_uri)

    logger.debug("`logstash` output plugin has been registered.")
  end

  def multi_receive(events)
    return if events.empty?

    send_events(events)
  end

  def stop
    logger.debug("Stopping `logstash` output plugin.")
    # TODO: what should we stop?
    logger.debug("`logstash` output plugin has been stopped.")
  end

  def close
    logger.debug("Closing `logstash` output plugin.")
    client.close
    logger.debug("`logstash` output plugin has been closed.")
  end

  def pipeline_shutdown_requested?
    return super if defined?(super) # since LS 8.1.0
    nil
  end

  private

  def validate_auth_settings!
    if @username
      fail(LogStash::ConfigurationError, '`password` is REQUIRED when `username` is provided') if @password.nil?
      logger.warn("transmitting credentials over non-secured connection") if @ssl_enabled == false
    elsif @password
      fail(LogStash::ConfigurationError, '`password` not allowed unless `username` is configured')
    end
  end

  def validate_ssl_identity_options!
    if @ssl_certificate && @ssl_keystore_path
      fail(LogStash::ConfigurationError, 'SSL identity can be configured with EITHER `ssl_certificate` OR `ssl_keystore_*`, but not both')
    elsif @ssl_certificate
      fail(LogStash::ConfigurationError, "`ssl_key` is REQUIRED when `ssl_certificate` is provided") if @ssl_key.nil?
    elsif @ssl_key
      fail(LogStash::ConfigurationError, '`ssl_key` is not allowed unless `ssl_certificate` is configured')
    elsif @ssl_keystore_path
      fail(LogStash::ConfigurationError, "`ssl_keystore_password` is REQUIRED when `ssl_keystore_path` is provided") if @ssl_keystore_password.nil?
    elsif @ssl_keystore_password
      fail(LogStash::ConfigurationError, "`ssl_keystore_password` is not allowed unless `ssl_keystore_path` is configured")
    else
      # acceptable
    end
  end

  def validate_ssl_trust_options!
    if @ssl_certificate_authorities&.any? && @ssl_truststore_path
      fail(LogStash::ConfigurationError, 'SSL trust can be configured with EITHER `ssl_certificate_authorities` OR `ssl_truststore_*`, but not both')
    elsif @ssl_certificate_authorities&.any?
      fail(LogStash::ConfigurationError, 'SSL Certificate Authorities cannot be configured when `ssl_verification_mode => none`') if @ssl_verification_mode == 'none'
    elsif @ssl_truststore_path
      fail(LogStash::ConfigurationError, 'SSL Truststore cannot be configured when `ssl_verification_mode => none`') if @ssl_verification_mode == 'none'
      fail(LogStash::ConfigurationError, '`ssl_truststore_password` is REQUIRED when `ssl_truststore_path` is provided') if @ssl_truststore_password.nil?

    elsif @ssl_truststore_password
      fail(LogStash::ConfigurationError, '`ssl_truststore_password` not allowed unless `ssl_truststore_path` is configured')
    end
  end

  def construct_host_uri
    scheme = @ssl_enabled ? 'https'.freeze : 'http'.freeze
    [].tap do |downstream_uris|
      @hosts.each do | host_port_pair | # Struct(:host, :port)
        uri = LogStash::Util::SafeURI.new(host_port_pair[:host])
        uri.port = host_port_pair[:port].nil? ? DEFAULT_PORT : host_port_pair[:port]
        uri.update(:scheme, scheme)
        # we only need `SafeURI::String` to directly apply to Manticore client
        downstream_uris << uri.to_s.freeze
      end
    end
  end

  def send_events(events)
    # we use array to utilize `peek` feature, note that every thread has its own array here
    pending = Array.new
    pending << [:send, events, 0]

    while (popped = pending.shift)
      action, events, attempt = popped
      break if action == :done

      # this may happen when _all_ upstream inputs are unreachable (ex: timeout) and we are _retrying_ to send events
      raise PluginInternalQueueLeftoverError.new("Received pipeline shutdown request but Logstash output has unfinished events. " \
              "If persistent queue is enabled, events will be retried.") if attempt > 2 && pipeline_shutdown_requested?

      # TODO: what if all hosts are unreachable in a given cool_off period?
      # sleep? or drop the event
      # also, retry doesn't have any meaning if all hosts are unreachable

      @router.route do | selected_host |
        action, events, attempt = send_event(selected_host.uri, events, attempt)

        if action == :retry
          # we retry to send to next available host decided by router
          attempt += 1
          pending << [action, events, attempt]
        else
          pending << [:done, events, attempt]
          # we don't need to catch the `:failure`, it is already logged
          # and decided if it needs to retry in `this#send_event`
        end
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

  def send_event(uri, events, attempt)
    body = LogStash::Json.dump(events.map {|e| e.to_hash })

    # Compress the body
    headers = @headers
    headers["Content-Encoding"] = "gzip"
    body = gzip(body)

    response = client.send(HTTP_METHOD, uri, :body => body, :headers => headers).call

    if !response_success?(response)
      if RETRIABLE_CODES.include?(response.code)
        if response.code == 429
          logger.debug? && logger.debug("Encountered a retriable 429 response.")
        else
          logger.warn("Encountered a retryable request in `logstash` output", :code => response.code, :body => response.body)
        end
        return :retry, events, attempt
      else
        logger.error("Encountered error",
                     :response_code => response.code,
                     :host => uri,
                     :events => events
        )
        return :failure, events, attempt
      end
    else
      return :success, events, attempt
    end

  rescue => exception
    will_retry = retryable_exception?(exception)
    log_entry = {
      :host => uri,
      :message => exception.message,
      :class => exception.class,
      :will_retry => will_retry
    }
    if logger.debug?
      # backtraces are big
      log_entry[:backtrace] = exception.backtrace
      # body can be big and may have sensitive data
      log_entry[:body] = body
    end
    logger.error("Could not send data to host", log_entry)

    if will_retry
      return :retry, events, attempt
    else
      return :failure, events, attempt
    end
  end

  def gzip(data)
    gz = StringIO.new
    gz.set_encoding("BINARY")
    z = Zlib::GzipWriter.new(gz)
    z.write(data)
    z.close
    gz.string
  end

  def response_success?(response)
    response.code >= 200 && response.code <= 299
  end

  def retryable_exception?(exception)
    retryable_manticore_exception?(exception) || retryable_unknown_exception?(exception)
  end

  def retryable_manticore_exception?(exception)
    RETRYABLE_MANTICORE_EXCEPTIONS.any? {|me| exception.is_a?(me)}
  end

  def retryable_unknown_exception?(exception)
    exception.is_a?(::Manticore::UnknownException) &&
      RETRYABLE_EXCEPTION_MESSAGES.any? { |snippet| exception.message =~ snippet }
  end

  def retryable_response?(response)
    RETRIABLE_CODES.include?(response.code)
  end

end