require 'logger'

class Rack::Auth::OCTanner::Token
  def initialize(app, options = {})
    if ENV['RACK_AUTH_OCTANNER_DEBUG'] || !options[:log]
      @logger = ::Logger.new(STDERR)
    else
      @logger = options[:log]
    end
    @app = app
    @options = options
  end

  def token_overridden?
    unless instance_variable_defined? :@token_overridden
      @token_overridden = !!ENV['OCTANNER_AUTH_TOKEN']
    end
    @token_overridden
  end

  def call(env)
    @env = env.dup
    begin
      @env['octanner_auth_user'] = decode_token token
    rescue StandardError => e
      @logger.error e
      @logger.error e.backtrace[0..9].join("\n")
    end
    @app.call(@env)
  end

  def decode_token(token)
    return nil if token.nil? || token.empty?
    data = packet.unpack(token)
    data['s'] = Rack::Auth::OCTanner::ScopeList.bytes_to_int data['s'] if data
    data['token'] = token if data
    data
  end

  private

  def token
    if token_overridden?
      token = ENV['OCTANNER_AUTH_TOKEN']
    else
      token = ENV['OCTANNER_AUTH_TOKEN'] = token_from_headers || token_from_params
    end
  end

  def request
    request ||= Rack::Request.new @env  # todo is 'request' a local variable here? why?
  end

  def token_from_params
    return request.params['bearer_token'] if request.params['bearer_token']

    # 'access_token' deprecated; we're moving to just Bearer tokens
    return request.params['access_token'] if request.params['access_token']
  end

  # 'Token token=' and 'Bearer token=' are deprecated; ; we're moving to just Bearer tokens
  def token_from_headers
    request.env['HTTP_AUTHORIZATION'] &&
    !request.env['HTTP_AUTHORIZATION'][/(oauth_version='1.0')/] &&
    request.env['HTTP_AUTHORIZATION'][/^(Bearer|Token) (token=)?([^\s]*)$/, 3]
  end

  def packet
    @packet ||= SimpleSecrets::Packet.new @options[:key]
  end
end
