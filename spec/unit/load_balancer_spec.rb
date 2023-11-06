# encoding: utf-8

require_relative "../spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/utils/load_balancer"

#
# The following is a high-level validation of CURRENT implementation
# that is tightly-coupled with initial state and is NOT a specification
# of the behaviour once its initial state has been invalidated by use.
#
# A formal validation of the load balancer's behaviour is forthcoming.
#
describe LoadBalancer do
  let(:downstream_infos) { %w[1.1.1.1:9801 2.2.2.2:9802 3.3.3.3:9803] }

  subject(:load_balancer) { described_class.new(downstream_infos) }

  describe "#initialize" do
    it "checks initialized params" do
      expect(load_balancer.instance_variable_get(:@cool_off)).to eq(60)
      expect(load_balancer.instance_variable_get(:@host_states)).to be_an(Array)
      expect(load_balancer.instance_variable_get(:@host_states).size).eql? 3
    end
  end

  describe "#route" do

    describe "with successful data transfer" do

      it "picks up the candidate host based on last request time" do
        # for the 1st call returns the 1.1.1.1, for the 2nd call returns 2.2.2.2 and so on
        downstream_infos.each do |host_uri |
          load_balancer.select do | selected_host_uri |
            expect(selected_host_uri).to eq(host_uri)
          end
        end
      end

    end

    describe "when data transfer fails" do

      it "applies the cool_off period for the next routes, marks host as error" do
        # sending events to "1.1.1.1:9801" fails, fair load balancer marks the host errored
        begin
          load_balancer.select do | selected_host_uri |
            expect(selected_host_uri).to eq("1.1.1.1:9801")
            raise "Cannot reach the host"
          end
        rescue
          # Ignore
        end

        # retry sends to "2.2.2.2:9802"
        %w[2.2.2.2:9802 3.3.3.3:9803].each do |host|
          load_balancer.select do | selected_host_uri |
            expect(selected_host_uri).to eq(host)
          end
        end

        # make sure errored host doesn't get requests in 60s

      end
    end
  end
end