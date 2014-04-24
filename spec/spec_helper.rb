require 'simplecov'
SimpleCov.start

SimpleCov.minimum_coverage 100

SimpleCov.at_exit do
  SimpleCov.result.format!
  if SimpleCov.result.covered_percent < SimpleCov.minimum_coverage
    fail_msg = "#{'%.2f' % SimpleCov.result.covered_percent}% test coverage?? Really??!!"
    STDERR.puts "\033[0;31m#{fail_msg}\033[0m\nWrite more tests"
    exit 1
  end
end

require 'rack/test'
require 'rack-auth-oc_tanner'
require 'ostruct'
RSpec.configure do |config|
  config.order = "random"
end
