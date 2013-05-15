module Rack
  module Auth
    class OCTanner
      def initialize(app, options = {})
        @app = app
        @options = options
      end

      def call(env)
        @env = env.dup
        debug env: env
        user = auth_user
        @env['oauth2_token_data'] = user
        @env['octanner_auth_user'] = user
        @app.call(@env)
      rescue StandardError => e
        STDERR.puts e
        @app.call(@env)
      end

      def auth_user
        packet.unpack (token_from_headers || token_from_params)
      end

      private

      def request
        request ||= Rack::Request.new @env
      end

      def token_from_params
        request.params['access_token']
      end

      def token_from_headers
        request.env['HTTP_AUTHORIZATION'] &&
        !request.env['HTTP_AUTHORIZATION'][/(oauth_version='1.0')/] &&
        request.env['HTTP_AUTHORIZATION'][/^Token token=?([^\s]*)$/, 1]
      end

      def packet
        @packet ||= SimpleSecrets::Packet.new @options[:key]
      end

      def debug(msg)
        STDERR.puts "Rack::Auth::OCTanner #{msg.inspect}" if ENV['RACK_AUTH_OCTANNER_DEBUG']
      end
    end
  end
end

