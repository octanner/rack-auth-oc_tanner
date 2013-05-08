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
        @env = env.dup

        @env['octanner_auth_client'] = auth_client
        @env['octanner_auth_user'] = auth_user
        @app.call(@env)

        # For now, note the error, set the token information
        # to nil, and send the request along; upstream will handle it
      rescue StandardError => e
        # p "Failed to authorize OAuth2:  #{e.message}"
        # return [401, {},[]]
        env['octanner_auth_client'] = nil
        env['octanner_auth_user'] = nil
        @app.call(env)
      end

      def auth_client
        token_from_request request
      end

      def auth_user
        validate_token auth_client
      end

      def token_string_from_request(request)
        return nil unless request
        token_string_from_params(request.params) || token_string_from_headers(request.env)
      end

      # Presently, this does a call out to the OAuth2 provider to validate
      # and retrieve user information.  In the future, this information may be
      # encoded into the token itself.
      def validate_token(token)
        response = token.get user_resource_url
        JSON.parse response.body
      end

      def token_from_request(request)
        token_string = token_string_from_request request
        access_token = OAuth2::AccessToken.new oauth2_client, token_string
      end

      private

      def request 
        @request ||= Rack::Request.new @env
      end

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

      def user_resource_url
        client_params[:site] + '/api/userinfo'
      end

      def oauth2_client
        @client ||= OAuth2::Client.new client_id, client_secret, client_params
      end

      def client_id
        @options[:client_id]
      end

      def client_secret
        @options[:client_secret]
      end

      def client_params
        {
          site: @options[:site] || 'https://api.octanner.com',
          authorize_url: @options[:authorize_url] || '/dialog/authorize',
          token_url: @options[:token_url] || '/oauth/token'
        }
      end

    end
  end
end

