require "logstash/devutils/rake"
require "rake/clean"

CLEAN << "spec/fixtures/certs/generated"
task :generate_test_certs do
  sh "spec/fixtures/certs/generate.sh" unless File.directory?("spec/fixtures/certs/generated")
end

task :vendor => :generate_test_certs