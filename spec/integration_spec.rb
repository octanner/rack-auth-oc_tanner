require 'rack/auth/oc_tanner'
require 'rack/test'

# Simple integration test for middleware
#
# run with rspec -t api
#
# Add CLIENT_ID, CLIENT_SECRET, SITE, and TOKEN to your environment
# You can obtain a token with this command just subsitute your credentials
# curl -d "grant_type=password" -d "username=USERNAME" -d "password=PASSWORD" 'https://CLIENT_ID:CLIENT_SECRET@oc-eve-prod.herokuapp.com/oauth/token'


describe Rack::Auth::OCTanner do
  include Rack::Test::Methods

  def app
    Rack::Builder.new do
      map "/" do
        use Rack::Auth::OCTanner, client_id: ENV['OAUTH_ID'], client_secret: ENV['OAUTH_SECRET'], site: ENV['OAUTH_SITE']
        run lambda { |env| 
          if env['oauth2_token_data']
            [200, { 'Content-Type' => 'text/plain' },'OK']
          else
            [500, { 'Content-Type' => 'text/plain' }, 'OAUTH2_TOKEN_DATA is nil']
          end
        }
      end
    end
  end

  it "should authenticate a valid token", :api => true do
    token = ENV['TOKEN'] 
    response = get "/?access_token=#{token}"
    response.status.should be 200
  end

  it "should not authenticate an invalid token", :api => true do
    token = :should_not_be_valid
    response = get "/?access_token=#{token}"
    response.status.should be 500
  end
end
