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

  describe '#call' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'should set env objects if authentication succeeds' do
      env = make_env 'HTTP_AUTHORIZATION' => "Token token=#{token}"
      subject.should_receive(:auth_user).with(token).and_return(user_info)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should eq user_info
    end

    it 'should set the token in the request env' do
      env = make_env 'HTTP_AUTHORIZATION' => "Token token=#{token}"
      subject.should_receive(:auth_user).with(token).and_return(user_info)
      response = subject.call(env)
      response[1]['octanner_auth_user']['token'].should eq token
    end

    it 'should set env objects to nil if authentication fails' do
      env = make_env 'HTTP_AUTHORIZATION' => "Token token=#{token}"
      subject.should_receive(:auth_user).with(token).and_return(nil)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should be_nil
    end

    it "should use headers over parameters for the auth token" do
      subject.should_receive(:token_from_headers).once.and_return(token)
      subject.should_not_receive(:token_from_params)
      subject.should_receive(:auth_user).with(token).and_return(nil)      
      subject.call(make_env)
    end

    it "should use the access_token parameter if no http headers present" do
      subject.should_receive(:token_from_headers).once.and_return(nil)
      subject.should_receive(:token_from_params).once.and_return(token)
      subject.should_receive(:auth_user).with(token).and_return(nil)
      subject.call(make_env)
    end

    it "should return nil if both token_from_headers and token_from_params are nils" do
      subject.should_receive(:token_from_headers).once.and_return(nil)
      subject.should_receive(:auth_user).with(nil).and_return(nil)
      response = subject.call(make_env)
      response[1]['octanner_auth_user'].should be_nil
    end

    it "should return nil if token_from_headers is empty" do
      env = make_env 'HTTP_AUTHORIZATION' => "Token token="
      subject.should_receive(:token_from_headers).once.and_return('')
      subject.should_receive(:auth_user).with('').and_return(nil)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should be_nil
    end

    it "should return nil if token_from_headers is empty" do
      env = make_env 'HTTP_AUTHORIZATION' => "Token token=#{token}"
      subject.should_receive(:auth_user).with(token).and_raise(StandardError)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should be_nil
    end

  end

  describe '#auth_user' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'returns an object if matches access_token' do
      subject.auth_user(token).should eq user_info
    end

    it 'returns nil if nothing matches' do
      subject.auth_user('bad1234').should eq nil
    end
  end
end
