require 'spec_helper'

def make_env(params = {})
  {
    'REQUEST_METHOD' => 'GET',
    'rack.session' => {},
    'rack.input' => StringIO.new('test=true')
  }.merge params
end


describe Rack::Auth::OCTanner do

  let(:app){ lambda { |env| [200, {}, []] } }
  let(:master_key){ "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" }
  let(:options){ { key: master_key } }
  let(:middleware){ Rack::Auth::OCTanner.new app, options }

  let(:user_info){ { 'person_id' => '1', 'company_id' => '2', 'application_id' => '3', 'scopes' => [ 'foo' ] } }

  let(:packet){ SimpleSecrets::Packet.new options[:key] }
  let(:token){ packet.pack user_info }

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
      env = make_env 'HTTP_AUTHORIZATION' => "Bearer token=#{token}"
      response = subject.call(env)
      env['oauth2_token_data'].should eq user_info
    end

    it 'should set env objects to nil if authentication fails' do
      env = make_env
      response = subject.call(env)
      env['oauth2_token_data'].should be_nil
    end

  end


  describe '#token_string_from_request' do

    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'returns nil if no request' do
      subject.token_string_from_request(nil).should be_nil
    end

    context 'with request params' do
      it 'matches bearer_token' do
        @request.params['bearer_token'] = token
        subject.token_string_from_request(@request).should eq token
      end

      it 'matches access_token' do
        @request.params['access_token'] = token
        subject.token_string_from_request(@request).should eq token
      end

      it 'matches oauth_token' do
        @request.params['oauth_token'] = token
        subject.token_string_from_request(@request).should eq token
      end
    end

    context 'with HTTP_AUTHORIZATION header' do
      it 'matches Bearer' do
        @request.env['HTTP_AUTHORIZATION'] = "Bearer token=#{token}"
        subject.token_string_from_request(@request).should eq token
      end

      it 'matches OAuth' do
        @request.env['HTTP_AUTHORIZATION'] = "OAuth token=#{token}"
        subject.token_string_from_request(@request).should eq token
      end

      it 'matches Token' do
        @request.env['HTTP_AUTHORIZATION'] = "Token token=#{token}"
        subject.token_string_from_request(@request).should eq token
      end
    end
  end
end