require 'spec_helper'

def make_env(params = {})
  {
    'REQUEST_METHOD' => 'GET',
    'rack.session' => {},
    'rack.input' => StringIO.new('test=true')
  }.merge params
end

describe Rack::Auth::OCTanner do
  let(:app) { lambda { |env| [200, env, []] }}
  let(:logger) { l = ::Logger.new(STDERR); l.level = Logger::FATAL; l } # silence output
  let(:options) {{ key: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", log: logger }}
  let(:user_info) {{ 'person_id' => '1', 'company_id' => '2', 'application_id' => '3', 'scopes' => [ 'foo' ] }}
  let(:token) { SimpleSecrets::Packet.new(options[:key]).pack user_info }
  let(:middleware) { Rack::Auth::OCTanner.new app, options }

  subject{ middleware }

  describe '#initialize' do
    it 'assigns the app variable' do
      subject.instance_variable_get( :@app ).should eq app
    end

    it 'creates a new logger by default' do
      middleware = Rack::Auth::OCTanner.new app, key: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
      middleware.instance_variable_get(:@logger).should be_a(::Logger)
    end

    it 'assigns the options variable' do
      subject.instance_variable_get( :@options ).should eq options
    end
  end

  describe "#token_overridden?" do
    it "always returns true if ENV token set by time of first call" do
      ENV['OCTANNER_AUTH_TOKEN'] = "any_thing_not_nil"
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.token_overridden?.should eq true
      ENV['OCTANNER_AUTH_TOKEN'] = nil
      subject.token_overridden?.should eq true
    end

    it "always returns false if ENV token unset by time of first call" do
      ENV['OCTANNER_AUTH_TOKEN'] = nil
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.token_overridden?.should eq false
      ENV['OCTANNER_AUTH_TOKEN'] = "any_thing_not_nil"
      subject.token_overridden?.should eq false
    end
  end

  describe '#call' do
    before :each do
      ENV['OCTANNER_AUTH_TOKEN'] = nil
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'should set env objects if authentication succeeds' do
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.should_receive(:decode_token).with(token).and_return(user_info)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should eq user_info
    end

    it 'should set the token in the request env' do
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      response = subject.call(env)
      response[1]['octanner_auth_user']['token'].should eq token
    end

    it "should set use the token in the ENV if set" do
      ENV['OCTANNER_AUTH_TOKEN'] = "the token"
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.should_receive(:decode_token).with("the token")
      response = subject.call(env)
    end

    it "should set the ENV with token if not initially set" do
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      response = subject.call(env)
      ENV['OCTANNER_AUTH_TOKEN'].should eq token
    end

    it 'should set env objects to nil if authentication fails' do
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.should_receive(:decode_token).with(token).and_return(nil)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should be_nil
    end

    it "should use headers over parameters for the auth token" do
      subject.should_receive(:token_from_headers).once.and_return(token)
      subject.should_not_receive(:token_from_params)
      subject.should_receive(:decode_token).with(token).and_return(nil)
      subject.call(make_env)
    end

    it "should use the access_token parameter if no http headers present" do
      subject.should_receive(:token_from_headers).once.and_return(nil)
      subject.should_receive(:token_from_params).once.and_return(token)
      subject.should_receive(:decode_token).with(token).and_return(nil)
      subject.call(make_env)
    end

    it "should return nil if both token_from_headers and token_from_params are nils" do
      subject.should_receive(:token_from_headers).once.and_return(nil)
      subject.should_receive(:decode_token).with(nil).and_return(nil)
      response = subject.call(make_env)
      response[1]['octanner_auth_user'].should be_nil
    end

    it "should return nil if token_from_headers is empty" do
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer "
      subject.should_receive(:token_from_headers).once.and_return('')
      subject.should_receive(:decode_token).with('').and_return(nil)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should be_nil
    end

    it "should return nil if token_from_headers is empty" do
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.should_receive(:decode_token).with(token).and_raise(StandardError)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should be_nil
    end

    # Deprecated; we're moving to 'Bearer' headers
    it "should support for 'Token token=' headers" do
      ENV['OCTANNER_AUTH_TOKEN'] = "the token"
      env = make_env 'HTTP_AUTHORIZATION' => "Token token=#{token}"
      subject.should_receive(:decode_token).with("the token")
      response = subject.call(env)
    end

    it "should support for 'Bearer token=' headers" do
      ENV['OCTANNER_AUTH_TOKEN'] = "the token"
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer token=#{token}"
      subject.should_receive(:decode_token).with("the token")
      response = subject.call(env)
    end

    it "should support for 'Bearer' headers" do
      ENV['OCTANNER_AUTH_TOKEN'] = "the token"
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer #{token}"
      subject.should_receive(:decode_token).with("the token")
      response = subject.call(env)
    end

  end

  describe '#decode_token' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'returns an object if matches access_token' do
      subject.decode_token(token).should eq user_info.merge({"token" => token})
    end

    it 'returns nil if nothing matches' do
      subject.decode_token('bad1234').should eq nil
    end
  end
end
