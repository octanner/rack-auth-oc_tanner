require 'simplecov'
SimpleCov.start

require 'rack/test'

require 'rack-auth-oc_tanner'
require 'ostruct'


RSpec.configure do |config|
  config.order = "random"
end
