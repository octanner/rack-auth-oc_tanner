require 'simple-secrets'

module Rack
  module Auth
    autoload :OCTanner, 'rack/auth/oc_tanner'
    autoload :AuthenticationFilter, 'rack/auth/authentication_filter'
  end
end

