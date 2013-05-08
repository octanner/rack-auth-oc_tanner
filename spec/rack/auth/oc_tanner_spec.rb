require 'spec_helper'

describe Rack::Auth::OCTanner do

  let(:app){ lambda { |env| [200, {}, []] } }
  let(:middleware){ Rack::Auth::OCTanner.new app, { client_id: '1', client_secret: 'secret' } }
  let(:mock_request){ Rack::MockRequest.new(middleware) }

  let(:token_string){ '1234567890' }
  let(:user_info){ { 'user_id' => '1', 'company_id' => '2', 'application_id' => '3', 'scopes' => [ 'foo' ] } }

  let(:user_info_url){ 'https://api.octanner.com/api/userinfo' }
  let(:user_info_ok){ { status: 200, body: user_info.to_json } }
  let(:user_info_unauthorized){ { status: 401 } }

  subject{ middleware }

  describe '#auth_user' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'should validate and return a valid user response' do
      client = double('token', get: double('response', body: user_info.to_json))
      subject.should_receive(:auth_client) { client }
      subject.auth_user.should eq user_info
    end
  end

  describe '#auth_client' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
      subject.should_receive(:request).at_least(1).times { @request }
    end

    it 'returns an OAuth2::AccessToken object' do
      subject.auth_client.should be_kind_of OAuth2::AccessToken
    end

  end

  describe '#token_string_from_request' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
      subject.should_receive(:request).at_least(1).times { @request }
    end

    context 'with request params' do
      it 'matches access_token' do
        @request.params['access_token'] = token_string
        subject.token.should eq token_string
      end
    end

    context 'with HTTP_AUTHORIZATION header' do
      it 'matches Token' do
        @request.env['HTTP_AUTHORIZATION'] = "Token token=#{token_string}"
        subject.token.should eq token_string
      end
    end
  end

end
