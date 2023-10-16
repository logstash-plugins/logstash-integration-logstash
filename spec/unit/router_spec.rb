# encoding: utf-8

require_relative "../spec_helper"
require "logstash/devutils/rspec/shared_examples"
require "logstash/outputs/router"

describe LogStash::Outputs::Logstash::Router do
  let(:downstream_infos) { %w[1.1.1.1:9801 2.2.2.2:9802 3.3.3.3:9803] }

  subject(:router) { described_class.new(downstream_infos) }

  describe "#initialize" do
    it "checks initialized params" do
      expect(router.instance_variable_get(:@cool_off)).to eq(60)
      expect(router.instance_variable_get(:@downstream_infos)).to be_an(Array)
      expect(router.instance_variable_get(:@downstream_infos).size).eql? 3
    end
  end

  describe "#route" do

    describe "when data transfer is successful" do

      it "picks up the candidate host based on last request time" do
        # for the 1st call returns the 1.1.1.1, for the 2nd call returns 2.2.2.2 and so on
        downstream_infos.each do |host_info |
          router.route do | selected_host |
            expect(selected_host.uri).to eq(host_info)
            expect(selected_host.concurrent).to eq(1)
            expect(selected_host).to receive(:decrement)
            expect(selected_host).not_to receive(:mark_error)
            [:done, nil, 0] # pretend to send the queue
          end
        end
      end

    end

    describe "when data transfer is failure" do

      it "applies the cool_off period for the next routes, marks host as error" do
        # sending events to "1.1.1.1:9801" fails, router marks the host errored
        router.route do | selected_host |
          expect(selected_host.uri).to eq("1.1.1.1:9801")
          expect(selected_host.concurrent).to eq(1)
          expect(selected_host).to receive(:decrement)
          expect(selected_host).to receive(:mark_error)
          [:retry, nil, 0] # pretend to send the queue
        end

        # retry sends to "2.2.2.2:9802"
        router.route do | selected_host |
          expect(selected_host.uri).to eq("2.2.2.2:9802")
          expect(selected_host.concurrent).to eq(1)
          expect(selected_host).to receive(:decrement)
          expect(selected_host).not_to receive(:mark_error)
          [:done, nil, 0] # pretend to send the queue
        end

        # TODO: sleep 60s and confirm resolving 1.1.1.1 again, manually tested
      end
    end
  end
end