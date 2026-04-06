# frozen_string_literal: true

$LOAD_PATH.unshift File.join(__dir__, '..', 'lib')

require 'webmock/rspec'
require 'vcr'
require 'audit/entitlement_auditor'
require 'audit/ssh_key_auditor'
require 'rbac/policy_engine'
require 'reports/report_generator'

VCR.configure do |config|
  config.cassette_library_dir = 'spec/cassettes'
  config.hook_into :webmock
  config.filter_sensitive_data('<GITHUB_TOKEN>') { ENV['GITHUB_TOKEN'] }
end

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
