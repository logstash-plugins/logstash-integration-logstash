require "monitor"

class FairLoadBalancer
  include MonitorMixin

  ##
  # Creates a new Router with the provided downstream_infos
  # that ignores errors older than the cool_off period
  # @param host_infos [Enumerable<HostSate>]: a list of downstream hosts
  #                                                       to include in routing
  # @param cool_off [Integer]: The cool_off period in seconds in which downstreams with
  #                           recent errors are de-prioritized (default: 60)
  def initialize(host_infos, cool_off: 60)
    super() # to initialize MonitorMixin

    fail ArgumentError, "Non-empty `host_infos` hosts required." unless host_infos&.any?
    fail ArgumentError, "`cool_off` requires integer value." unless cool_off.kind_of?(Integer)

    @cool_off = cool_off
    @downstream_infos = host_infos.map do |host_info|
      HostState.new(host_info)
    end
  end

  ##
  # Yields the block with a {HostState}, prioritizing
  # hosts that are less concurrently-used and which have
  # not errored recently.
  # @yield param selected [HostState]
  def select
    selected = synchronize { pick_one.tap(&:increment) }
    yield selected
  rescue
    synchronize { selected.mark_error }
    raise
  ensure
    synchronize { selected.decrement }
  end

  private

  def pick_one
    threshold = Time.now.to_i - @cool_off
    @downstream_infos.sort_by do |downstream_state|
      [
        [downstream_state.last_error, threshold].max, # deprioritize recent errors
        downstream_state.concurrent,                  # deprioritize high concurrency
        downstream_state.last_start                   # deprioritize recent use
      ]
    end.first
  end

  class HostState
    def initialize(host_uri)
      @uri = host_uri
      @concurrent = 0
      @last_start = 0
      @last_error = 0
    end
    attr_reader :uri
    attr_reader :concurrent
    attr_reader :last_start
    attr_reader :last_error

    def increment
      @concurrent += 1
      @last_start = Time.now.to_f
    end

    def decrement
      @concurrent -= 1
    end

    def mark_error
      @last_error = Time.now.to_f
    end
  end
end