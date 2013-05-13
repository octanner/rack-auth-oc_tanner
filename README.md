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
  config.middleware.use Rack::Auth::OCTanner, key: ENV['OCT_AUTH_KEY']
end
```

The `OCT_AUTH_KEY` should be an environment variable set to the shared secret key used to encrypt and decrypt the authentication tokens.  This parameter is required.



### Authenticating Requests

The `Rack::Auth::OCTanner` middleware will look for an OAuth2 token in the request parameters or headers, and will attempt to validate that token.  If the validation succeeds, the middleware will add the following object to the request environment:

`env['oauth2_token_data']` - A `Hash` of basic information representing the user associated with the token.  This may include the user's ID, their associated company ID, and any associated OAuth2 scopes.  The actual content will depend on the configuration of the OAuth2 provider service.

If the authentication fails, this value will be set to `nil`.


### Obtaining a token through HTTP

To obtain an OAuth2 token from the OC Tanner provider, submit a POST request including the client's credentials in the URL and the user's credentials are parameters:

```
https://client_id:client_secret@oc-eve-prod.herokuapp.com/oauth/token?grant_type=password&username=some_user&password=some_password
```

or with `curl`:
```
curl -d "grant_type=password" -d "username=some_user" -d "password=some_password" 'https://client_id:client_secret@oc-eve-prod.herokuapp.com/oauth/token'
```
The return will be JSON with the access token and token type.
