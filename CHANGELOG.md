## 1.0.0
  - Introduces the load balancing mechanism to distribute the requests among the `hosts` [#16](https://github.com/logstash-plugins/logstash-integration-logstash/pull/16)

## 0.0.5
  - [DOC] Fixes to link formatting [#15](https://github.com/logstash-plugins/logstash-integration-logstash/pull/15)

## 0.0.4
  - Simplify configuration [#13](https://github.com/logstash-plugins/logstash-integration-logstash/pull/13)
    - Introduce a default `port` of `9800` for both input and output plugins
    - BREAKING: Introduce `hosts` config to output plugin, _replacing_ its separate `host` and `port` configurations

## 0.0.3
  - [DOC] Minor doc changes and version bump to facilitate adding integration files to doc build [#14](https://github.com/logstash-plugins/logstash-integration-logstash/pull/14)

## 0.0.2
  - Enable data compression [#10](https://github.com/logstash-plugins/logstash-integration-logstash/pull/10)

## 0.0.1
  - Minimal bootstrap of Logstash to Logstash plugin [#1](https://github.com/logstash-plugins/logstash-integration-logstash/pull/2)
  - Complete bootstrap and fix documentation [#3](https://github.com/logstash-plugins/logstash-integration-logstash/pull/3)
  - Apply SSL standardization [#7](https://github.com/logstash-plugins/logstash-integration-logstash/pull/7)