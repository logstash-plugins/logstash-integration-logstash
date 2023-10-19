# encoding: utf-8

require "logstash/outputs/base"
require "logstash/namespace"

require "logstash/plugin_mixins/http_client"
require "logstash/plugin_mixins/validator_support/required_host_optional_port_validation_adapter"
require "zlib"

class LogStash::Outputs::Logstash < LogStash::Outputs::Base
  extend LogStash::PluginMixins::ValidatorSupport::RequiredHostOptionalPortValidationAdapter

  include LogStash::PluginMixins::HttpClient[:with_deprecated => false]

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

  def initialize(*a)
    super

    if original_params.include?('codec')
      fail LogStash::ConfigurationError, 'The `logstash` output does not have an externally-configurable `codec`'
    end

    @headers = {}.tap do | header |
      header["Content-Type"] = "application/x-ndjson"
      header["Content-Encoding"] = "gzip"
    end

    logger.debug("`logstash` output plugin has been initialized.")
  end

  def register
    logger.debug("Registering `logstash` output plugin.")

    # TODO: confirm if we have a plan to change @user to @username
    logger.warn("Both `user` and `username` are defined, using `username` value.") if @user && @username
    @user = @username ? @username.freeze : @user

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
    logger.debug("Stopping `logstash` output plugin.")
    # TODO: what should we stop?
    logger.debug("`logstash` output plugin has been stopped.")
  end

  def close
    logger.debug("Closing `logstash` output plugin.")
    @http_client.close
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
    pending = Queue.new
    pending << [:send, events, 0]

    while (popped = pending.pop)
      action, events, attempt = popped
      break if action == :done

      if pipeline_shutdown_requested?
        logger.info "Aborting the batch due to shutdown request."
        abort_batch_if_available!
      end

      # TODO: what if all hosts are unreachable?
      # current behaviour is to continuously observe if plugin can send the events

      body = LogStash::Json.dump(events.map {|e| e.to_hash })
      compressed_body = gzip(body)

      current_host_uri = ""
      begin
        response = @load_balancer.select do | selected_host_uri |
          current_host_uri = selected_host_uri
          @http_client.send(HTTP_METHOD, selected_host_uri, :body => compressed_body, :headers => @headers).call
        end
        action = analyze_response(current_host_uri, response, events)
      rescue => exception
        action = analyze_exception(current_host_uri, exception, body)
      end

      if action == :retry
        # we retry to send to next available host decided by router
        attempt += 1
        pending << [action, events, attempt]
      else
        pending << [:done, events, attempt]
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

  def analyze_response(uri, response, events)
    return :success if response_success?(response)

    if retryable_response?(response.code)
      if response.code == 429
        logger.debug? && logger.debug("Encountered a retriable 429 response.")
      else
        logger.warn("Encountered a retryable request in `logstash` output", :code => response.code, :body => response.body)
      end
      return :retry
    else
      logger.error("Encountered error",
                   :response_code => response.code,
                   :host => uri,
                   :events => events
      )
      return :failure
    end
  end

  def analyze_exception(uri, exception, body)
    will_retry = retryable_exception?(exception)
    log_entry = { :host => uri, :message => exception.message, :class => exception.class, :will_retry => will_retry }
    if logger.debug?
      # backtraces are big
      log_entry[:backtrace] = exception.backtrace
      # body can be big and may have sensitive data
      log_entry[:body] = body
    end
    logger.error("Could not send data to host", log_entry)

    will_retry ? :retry : :failure
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