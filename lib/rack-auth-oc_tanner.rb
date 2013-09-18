require 'simple-secrets'

module Rack::Auth::OCTanner
  autoload :Token, 'rack/auth/oc_tanner/token'
  autoload :AuthenticationFilter, 'rack/auth/oc_tanner/authentication_filter'
  autoload :SmD, 'rack/auth/oc_tanner/smd'
  autoload :ScopeList, 'rack/auth/oc_tanner/scope_list'
  autoload :Scopes, 'rack/auth/oc_tanner/scopes'
  autoload :SmallHour, 'rack/auth/oc_tanner/small_hour'

  class UndefinedScopeError < StandardError; end

  def self.scopes
    @@scope_list ||= ScopeList.new ENV['SCOPES']
  end
end
