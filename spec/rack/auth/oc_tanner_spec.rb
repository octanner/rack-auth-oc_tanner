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
  let(:options) {{ key: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" }}
  let(:user_info) {{ 'person_id' => '1', 'company_id' => '2', 'application_id' => '3', 'scopes' => [ 'foo' ] }}
  let(:token) { SimpleSecrets::Packet.new(options[:key]).pack user_info }
  let(:middleware) { Rack::Auth::OCTanner.new app, options }

  subject{ middleware }

  describe '#initialize' do
    it 'assigns the app variable' do
      subject.instance_variable_get( :@app ).should eq app
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
      response[1]['octanner_auth_token'].should eq token
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
      env = make_env
      response = subject.call(env)
    end

    it "should use the access_token parameter if no http headers present" do
      subject.should_receive(:token_from_headers).once.and_return(nil)
      subject.should_receive(:token_from_params).once.and_return(token)
      subject.should_receive(:auth_user).with(token).and_return(nil)
      env = make_env
      response = subject.call(env)
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
