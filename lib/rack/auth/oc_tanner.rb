module Rack
  module Auth
    class OCTanner
      def initialize(app, options = {})
        options[:debug] = true if ENV['RACK_AUTH_OCTANNER_DEBUG']
        @app = app
        @options = options
      end

      def call(env)
        @env = env.dup
        debug env: env
        token = token_from_headers || token_from_params
        user = auth_user(token)
        if user
          @env['octanner_auth_user'] = user
          @env['octanner_auth_user']['token'] = token
        end
        @app.call(@env)
      rescue StandardError => e
        STDERR.puts e
        STDERR.puts e.backtrace[0..9].join("\n")
        @app.call(@env)
      end

      def auth_user(token)
        debug "Decrypting Token: #{token.inspect} with #{@options[:key]}"
        data = packet.unpack(token)
        debug "Data: #{data.inspect}"
        data
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
        STDERR.puts "Rack::Auth::OCTanner #{msg.inspect}" if @options[:debug]
      end
    end
  end
end

