require 'logger'

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
    return nil if token.nil? || token.empty?

    # if its JWT token then check for core authentication
    # if core authentication is not success then check for admin authentication
    # if its not JWT token check for user authentication
    if jwt_token?(token)
      begin
        decode_core_auth_token token
      rescue Exception => e
        decode_admin_auth_token token
      end
    else
      decode_token token
    end
  end

  # For user authentication
  def decode_token(token)
    return nil if token.nil? || token.empty?

    data = packet.unpack(token)
    data['s'] = Rack::Auth::OCTanner::ScopeList.bytes_to_int data['s'] if data
    data['token'] = token if data
    data
  end

  # For core auth authentication
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

  # For admin auth authentication
  def decode_admin_auth_token(token)
    return nil if token.nil? || token.empty?

    data = decode_jwt_admin_token(token)

    if data
      activities = data['activities'].first

      if validate_admin_auth_response activities
        data['authToken'] = token
        data['u'] = data['systemUserId']
      end
    end

    data
  end

  private

  # validate if decode response contains 'ADMIN_HOME' & 'ADMIN_GROUP_DEPOSITS'
  def validate_admin_auth_response(parent_activities)
    if parent_activities['id'] == 'ADMIN_HOME'
      if parent_activities.length.positive?
        children_activites = parent_activities['children']
        children_activites.select { |activity|
          activity[:id] == 'ADMIN_GROUP_DEPOSITS'
        }.length.positive?
      else
        false
      end
    else
      false
    end
  end

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

  def decode_jwt_admin_token(token)
    admin_url = if ENV.fetch('ADMIN_AUTH_URL').nil?
                 'https://vision.appreciatehub.com/api/auth/validate'
               else
                 ENV.fetch('ADMIN_AUTH_URL')
               end

    req = validate_admin_token(admin_url, token)

    response = http.start { |http| http.request req }

    if response.code >= '200' && response.code <= '204'
      JSON.parse(response.body).with_indifferent_access
    end
  end

  def jwks
    response = Net::HTTP.get_response(URI(ENV.fetch('CORE_JWKS_URL')))
    JSON.parse(response.body).with_indifferent_access
  end

  def validate_admin_token(uri, token)

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true if uri.scheme == 'https'
    request = Net::HTTP::Get.new uri
    request['Authorization'] = 'Bearer ' + token
    request
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
