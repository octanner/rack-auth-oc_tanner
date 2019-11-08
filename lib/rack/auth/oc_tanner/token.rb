require 'json'
require 'jwt'
require 'logger'
require 'net/http'


class Rack::Auth::OCTanner::Token
  def initialize(app, options = {})

    @logger =
        if ENV['RACK_AUTH_OCTANNER_DEBUG'] || !options[:log]
          ::Logger.new(STDERR)
        else
          options[:log]
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
      @env['octanner_auth_user'] = auth_token_data(token)

    rescue StandardError => e
      @logger.error e
      @logger.error e.backtrace[0..9].join("\n")
    end

    @app.call(@env)
  end

  def auth_token_data(token)
    user_info =
      if jwt_token?(token)
        decode_core_auth_token token
      else
        decode_token token
      end

    user_info
  end

  def decode_token(token)
    return nil if token.nil? || token.empty?

    data = packet.unpack(token)
    data['s'] = Rack::Auth::OCTanner::ScopeList.bytes_to_int data['s'] if data
    data['token'] = token if data
    data
  end

  def decode_core_auth_token(token)
    return nil if token.nil? || token.empty?

    data = decode_jwt_token(token)

    if data
      data = data.first
      data['token'] = token
      data['u'] = data['sub']
    end

    data
  end

  private

  def token
    if token_overridden?
      token = ENV['OCTANNER_AUTH_TOKEN']
    else
      token = ENV['OCTANNER_AUTH_TOKEN'] = token_from_headers || token_from_params || token_from_cookies
    end
  end

  def request
    request ||= Rack::Request.new @env  # todo is 'request' a local variable here? why?
  end

  def token_from_cookies
    return request.cookies['_access_token'] || request.cookies['_bearer_token']
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

  def decode_jwt_token(token)

    verify_options = {
        algorithm: 'RS256',
        verify_iat: true,
        jwks: jwks
    }

    JWT.decode(token, nil, true, verify_options)
  end

  def jwks
    response = Net::HTTP.get_response(URI(ENV.fetch('CORE_JWKS_URL')))
    JSON.parse(response.body).with_indifferent_access
  end

  def jwt_token?(token)
    parts = token.split('.')
    jwt_singed_token?(parts) || jwt_un_singed_token?(parts, token)
  end

  def jwt_singed_token?(parts)
    no_of_jwt_signed_parts = 3
    parts.length == no_of_jwt_signed_parts
  end

  def jwt_un_singed_token?(parts, token)
    no_of_jwt_unsigned_parts = 2
    (parts.length == no_of_jwt_unsigned_parts && token.end_with('.'))
  end

end
