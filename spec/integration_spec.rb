require 'rack/auth/oc_tanner'
require 'rack/test'

# Simple integration test for middleware
#
## Setup
#
# The test depends on OAUTH_ID, OAUTH_SECRET, OAUTH_SITE, and TOKEN being in the evironment
#
#   $ export OAUTH_ID=your_client_id
#   etc.
#
# You can obtain a token with this command just subsitute your credentials
# curl -d "grant_type=password" -d "username=USERNAME" -d "password=PASSWORD" 'https://OAUTH_ID:OAUTH_SECRET@oc-eve-prod.herokuapp.com/oauth/token'
#
## Running the test
#
#   $ rspec -t api spec/integration_spec.rb

describe Rack::Auth::OCTanner do
  include Rack::Test::Methods

  def app
    Rack::Builder.new do
      map "/" do
        use Rack::Auth::OCTanner, client_id: ENV['OAUTH_ID'], client_secret: ENV['OAUTH_SECRET'], site: ENV['OAUTH_SITE']
        run lambda { |env|
          if env['octanner_auth_user']
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
