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
      response = subject.call(env)
      response[1]['oauth2_token_data'].should eq user_info
    end

    it 'should set env objects to nil if authentication fails' do
      env = make_env
      response = subject.call(env)
      response[1]['oauth2_token_data'].should be_nil
    end
  end

  describe '#auth_user' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
      subject.should_receive(:request).at_least(1).times { @request }
    end

    context 'with request params' do
      it 'matches access_token' do
        @request.params['access_token'] = token
        subject.auth_user.should eq user_info
      end
    end

    context 'with HTTP_AUTHORIZATION header' do
      it 'matches Token' do
        @request.env['HTTP_AUTHORIZATION'] = "Token token=#{token}"
        subject.auth_user.should eq user_info
      end
    end

    context 'with HTTP_AUTHORIZATION header and request params' do
      it 'header takes precedence when invalid' do
        @request.params['access_token'] = token
        subject.auth_user.should eq user_info
        @request.env['HTTP_AUTHORIZATION'] = "Token token=#{"abcdefg"}" # Invald token
        subject.auth_user.should eq nil
      end

      it 'header takes precedence when valid' do
        @request.params['access_token'] = "abcdefg" # Invalid token
        subject.auth_user.should eq nil
        @request.env['HTTP_AUTHORIZATION'] = "Token token=#{token}"
        subject.auth_user.should eq user_info
      end
    end
  end
end
