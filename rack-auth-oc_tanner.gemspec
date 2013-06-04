Gem::Specification.new do |gem|
  gem.name = 'rack-auth-oc_tanner'
  gem.version = '0.9.3'

  gem.authors = ['Jay Wagnon']
  gem.email = ['jay.wagnon@octanner.com']

  gem.description = %q{Rack module for handling OC Tanner authentication tokens.}
  gem.summary = gem.description
  gem.homepage = 'https://github.com/octanner/rack-auth-oc_tanner'

  gem.files = [
    'lib/rack-auth-oc_tanner.rb',
    'lib/rack/auth/oc_tanner.rb'
  ]
  gem.require_paths = %w[lib]

  gem.test_files = %w[]

  gem.add_dependency 'rack'
  gem.add_dependency 'simple-secrets', '~> 1.0.0'
  gem.add_development_dependency 'guard-rspec'
end
