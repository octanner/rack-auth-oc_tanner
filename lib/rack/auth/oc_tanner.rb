require 'oauth2'
require 'json'

module Rack
  module Auth
    class OCTanner

      def initialize(app, options = {})
        @app = app
        @options = options
      end


      def call(env)
        request = Rack::Request.new(env)

        token = token_from_request request
        env['oauth2_token_data'] = validate_token token
        env['oauth2_token'] = token
        @app.call(env)

        # For now, note the error, set the token information
        # to nil, and send the request along; upstream will handle it
      rescue StandardError => e
        # p "Rack::Auth::OCTanner failed to authorize:  #{e.message}"
        # return [401, {},[]]
        env['oauth2_token_data'] = nil
        env['oauth2_token'] = nil
        @app.call(env)
      end


      # Presently, this does a call out to the OAuth2 provider to validate
      # and retrieve user information.  In the future, this information may be
      # encoded into the token itself.
      def validate_token(token)
        response = token.get oauth2_client.site + '/api/userinfo'
        JSON.parse response.body
      end


      def token_from_request(request)
        token_string = token_string_from_request request
        access_token = OAuth2::AccessToken.new oauth2_client, token_string
      end


      def token_string_from_request(request)
        return nil unless request
        token_string_from_params(request.params) || token_string_from_headers(request.env)
      end


      private


      def token_string_from_params(params = {})
        params['bearer_token'] ||
        params['access_token'] ||
        (params['oauth_token'] && !params['oauth_signature'] ? params['oauth_token'] : nil )
      end


      def token_string_from_headers(headers = {})
        headers['HTTP_AUTHORIZATION'] &&
        !headers['HTTP_AUTHORIZATION'][/(oauth_version='1.0')/] &&
        headers['HTTP_AUTHORIZATION'][/^(Bearer|OAuth|Token) (token=)?([^\s]*)$/, 3]
      end


      def oauth2_client
        @client ||= OAuth2::Client.new(
          @options[:client_id],
          @options[:client_secret],
          { site: @options[:site] || 'https://api.octanner.com',
            authorize_url: @options[:authorize_url] || '/dialog/authorize',
            token_url: @options[:token_url] || '/oauth/token' })
      end
    end
  end
end

