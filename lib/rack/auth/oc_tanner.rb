require 'logger'

module Rack
  module Auth
    class OCTanner
      def initialize(app, options = {})
        if ENV['RACK_AUTH_OCTANNER_DEBUG'] || !options[:log]
          @logger = ::Logger.new(STDERR)
        else
          @logger = options[:log]
        end
        @app = app
        @options = options
      end

      def call(env)
        @env = env.dup
        begin
          token = token_from_headers || token_from_params
          user = auth_user(token)
          if user
            @env['octanner_auth_user'] = user
            @env['octanner_auth_user']['token'] = token
          end
        rescue StandardError => e
          @logger.error e
          @logger.error e.backtrace[0..9].join("\n")
        end
        @app.call(@env)
      end

      def auth_user(token)
        return nil if token.nil? || token.empty?
        debug "Decrypting Token: #{token.inspect} with #{@options[:key]}"
        data = packet.unpack(token)
        debug "Data: #{data.inspect}"
        data
      end

      private

      def request
        request ||= Rack::Request.new @env  # todo is 'request' a local variable here? why?
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

      private
      def debug(msg)
        @logger.debug "Rack::Auth::OCTanner #{msg.inspect}"
      end
    end
  end
end

