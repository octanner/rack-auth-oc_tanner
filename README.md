rack-auth-oc_tanner
===================

Rack module for handling OC Tanner OAuth2 tokens.



## Getting Started

```ruby
gem 'rack-auth-oc_tanner', git: 'https://github.com/octanner/rack-auth-oc_tanner.git'
```

Then run the bundle command to install it.



## Rails Intergration

### Configuration

Add the following to your config/applications.rb file

```ruby
class Application < Rails::Application
  config.middleware.use Rack::Auth::OCTanner, key: ENV['TOKEN_HEX_KEY']
end
```

The `TOKEN_HEX_KEY` should be an environment variable set to the shared secret key used to encrypt and decrypt the authentication tokens.  This parameter is required.



## Authenticating Requests

The `Rack::Auth::OCTanner` middleware will look for an OAuth2 token in the request parameters or headers, and will attempt to validate that token.  If the validation succeeds, the middleware will add the following object to the request environment:

`env['octanner_auth_user']` - A `Hash` of basic information representing the user associated with the token.  This may include the user's ID, their associated company ID, and any associated OAuth2 scopes.  The actual content will depend on the configuration of the OAuth2 provider service.

If the authentication fails, this value will be set to `nil`.



### Using Rails before_filter

The `Rack::Auth::OCTanner::AuthenticationFilter` can be used for quick authenticaiton in Rails controllers.  Add the following to the controller:

```ruby
before_filter Rack::Auth::OCTanner::AuthenticationFilter.new(scopes)
```

`scopes` is an optional array of OAuth2 scopes that are required to pass the filter (i.e. 'registration', 'user_read', etc.).  The token must qualify for all the scopes in the array to pass.

If the token is not present in the request or all of the required scopes are not met, the filter will return 401.



### Obtaining a token through HTTP

To obtain an OAuth2 token from the OC Tanner provider, submit a POST request including the client's credentials in the URL and the user's credentials are parameters:

```
https://client_id:client_secret@oc-eve-prod.herokuapp.com/oauth/token?grant_type=password&username=some_user&password=some_password
```

or with `curl`:
```
curl -d "grant_type=password" -d "username=some_user" -d "password=some_password" 'https://client_id:client_secret@accounts.octanner.com/oauth/token'
```
The return will be JSON with the access token and token type.
