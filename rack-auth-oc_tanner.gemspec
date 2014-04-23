Gem::Specification.new do |gem|
  gem.name = 'rack-auth-oc_tanner'
  gem.version = '1.0.1'

  gem.authors = ['Jay Wagnon']
  gem.email = ['jay.wagnon@octanner.com']

  gem.description = %q{Rack module for handling OC Tanner authentication tokens.}
  gem.summary = gem.description
  gem.homepage = 'https://github.com/octanner/rack-auth-oc_tanner'

  gem.files = %w(README.md rack-auth-oc_tanner.gemspec)
  gem.files += Dir.glob("lib/**/*.rb")
  gem.files += Dir.glob("spec/**/*.rb")
  gem.require_paths = %w[lib]

  gem.test_files = Dir.glob("spec/**/*")

  gem.add_dependency 'rack'
  gem.add_dependency 'simple-secrets', '~> 1.0.0'
  gem.add_dependency 'smd', '~> 1.0.0'
end
