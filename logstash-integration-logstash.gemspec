INTEGRATION_LOGSTASH_VERSION = File.read(File.expand_path(File.join(File.dirname(__FILE__), "VERSION"))).strip unless defined?(INTEGRATION_LOGSTASH_VERSION)

Gem::Specification.new do |s|
  s.name            = "logstash-integration-logstash"
  s.version         = INTEGRATION_LOGSTASH_VERSION
  s.licenses        = ["Apache-2.0"]
  s.summary         = "Collection of Logstash plugins that enable sending events from one Logstash pipeline to another"
  s.description     = "This gem is a Logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/logstash-plugin install gemname. This gem is not a stand-alone program"
  s.authors         = ["Elastic"]
  s.email           = "info@elastic.co"
  s.homepage        = "https://www.elastic.co/logstash"
  s.platform        = "java"
  s.metadata        = {
    "logstash_plugin" => "true",
    "logstash_group" => "integration",
    "integration_plugins" => %w(
      logstash-input-logstash
      logstash-output-logstash
    ).join(",")
  }

  s.require_paths   = %w[lib vendor/jar-dependencies]
  s.files           = Dir["lib/**/*","spec/**/*","*.gemspec","*.md","CONTRIBUTORS","Gemfile","LICENSE","NOTICE.TXT", "VERSION", "docs/**/*", "vendor/jar-dependencies/**/*.jar", "vendor/jar-dependencies/**/*.rb"]
  s.test_files      = s.files.grep(%r{^(test|spec|features)/})

  s.add_runtime_dependency "logstash-core-plugin-api", ">= 2.1.12", "<= 2.99"
  s.add_runtime_dependency "logstash-mixin-plugin_factory_support", "~> 1.0"
  s.add_runtime_dependency "logstash-codec-json_lines", "~> 3.1"

  s.add_runtime_dependency "logstash-input-http", ">= 3.7.2"  # some params renamed, such as `cacert` to `ssl_certificate_authorities`, do not exist in older versions
  s.add_runtime_dependency "logstash-output-http", ">= 5.6.0"

  s.add_development_dependency "logstash-devutils"
  s.add_development_dependency "rspec-collection_matchers"
  s.add_development_dependency "random-port"
end
