require "monitor"

module LogStash; module Outputs; class Logstash
  class Router
    include MonitorMixin

    ##
    # Sets a new Router with the provided downstream_infos
    # that ignores errors older than the cool_off period
    # @param downstream_infos [Enumerable<DownstreamInfo>]: a list of downstream hosts
    #                                                       to include in routing
    # @param cool_off [Integer]: The cool_off period in seconds in which downstreams with
    #                           recent errors are de-prioritized (default: 60)
    def initialize(downstream_infos, cool_off: 60)
      super() # to initialize MonitorMixin

      @cool_off = cool_off
      @downstream_infos = downstream_infos.map do |downstream_info|
        DownstreamState.new(downstream_info)
      end
    end

    ##
    # Yields the block with a {DownstreamState}, prioritizing
    # hosts that are less concurrently-used and which have
    # not errored recently.
    # @yield param selected [DownstreamState]
    def route
      selected = synchronize { pick_one.tap(&:increment) }
      processed_queue = yield selected
      action, _, _ = processed_queue.first
      synchronize { selected.mark_error } if action == :retry || action == :failure
    rescue
      # we don't _really_ get here, exceptions are handled in Logstash#send_event
      # and mark error in the main block of this#route but let's place it for the safety
      synchronize { selected.mark_error }
      raise
    ensure
      synchronize { selected.decrement }
    end

    private

    def pick_one
      # sort downstream states by giving enough cool off period after last error
      @downstream_infos.sort_by do |downstream_state|
        cool_off_threshold = downstream_state.last_error_time == 0 ? 0 : downstream_state.last_error_time + @cool_off
        [
          [downstream_state.last_request_time, cool_off_threshold].max,
          downstream_state.concurrent
        ]
      end.first
    end

    class DownstreamState
      def initialize(downstream_uri)
        @uri = downstream_uri
        @concurrent = 0
        @last_error_time = 0
        @last_request_time = 0
      end
      attr_reader :uri
      attr_reader :concurrent
      attr_reader :last_error_time
      attr_reader :last_request_time

      def increment
        @last_request_time = Time.now.to_i
        @concurrent += 1
      end

      def decrement
        @concurrent -= 1
      end

      def mark_error
        @last_error_time = Time.now.to_i
      end
    end
  end
end end end