module Rack
  module Auth
    class OCTanner

      def initialize(app, options = {})
        @app = app
        @options = options
      end


      def call(env)
        request = Rack::Request.new(env)
        token = token_string_from_request request
        env['oauth2_token_data'] = packet.unpack token
        @app.call(env)
      rescue StandardError => e
        env['oauth2_token_data'] = nil
        @app.call(env)
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


      def packet
        @packet ||= SimpleSecrets::Packet.new @options[:key]
      end
    end
  end
end

