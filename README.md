# rack-auth-oc_tanner

Rack middleware for handling OC Tanner OAuth2 tokens.

## Getting Started

Add the gem to your Gemfile, and bundle.

```ruby
gem 'rack-auth-oc_tanner', git: 'https://github.com/octanner/rack-auth-oc_tanner.git'
```

```
bundle install
```

## Rails Intergration

### Configuration

Add the following to your config/applications.rb

```ruby
class Application < Rails::Application
  config.middleware.use Rack::Auth::OCTanner, key: ENV['TOKEN_HEX_KEY']
end
```

Export the shared secret to TOKEN_HEX_KEY.

```
  export TOKEN_HEX_KEY="YOUR SHARED SECRET KEY"
```

## Authenticating Requests

The `Rack::Auth::OCTanner` middleware will look for an OAuth2 token in the
request parameters or headers, and will attempt to validate that token.  If the
validation succeeds, the middleware will add the following object to the
request environment: `env['octanner_auth_user']` - A `Hash` of basic
information representing the user associated with the token.  This may include
the user's ID, their associated company ID, and any associated OAuth2 scopes.
The actual content will depend on the configuration of the OAuth2 provider
service.

If the authentication fails, this value will be set to `nil`.

### Using Rails before_filter

The `Rack::Auth::OCTanner::AuthenticationFilter` can be used for quick
authenticaiton in Rails controllers.  Add the following to the controller:

```ruby
  before_filter Rack::Auth::OCTanner::AuthenticationFilter.new(scopes)
```

`scopes` is an optional array of OAuth2 scopes that are required to pass the
filter (i.e. 'registration', 'user_read', etc.).  The token must qualify for
all the scopes in the array to pass.

If the token is not present in the request or all of the required scopes are
not met, the filter will return 401.

## Obtaining Credentials

### Client Id and Secret

1. Ask Cammeron Bytheway for a client secret and client hash
2. Give the hash to Amela and ask for a client id
3. Authenticate with your client secret and client id

For information on how to use these to obtain a token see:
https://github.com/octanner/perf_auth_client.rb

`
