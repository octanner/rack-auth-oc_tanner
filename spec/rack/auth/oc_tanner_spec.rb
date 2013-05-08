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

  describe '#validate_token' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'should validate and return a valid user response' do
      token = double('token', get: double('response', body: user_info.to_json))
      subject.validate_token(token).should eq user_info
    end
  end

  describe '#token_from_request' do
    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
      subject.should_receive(:request).at_least(1).times { @request }
    end

    it 'returns an OAuth2::AccessToken object' do
      subject.token_from_request.should be_kind_of OAuth2::AccessToken
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
      it 'matches bearer_token' do
        @request.params['bearer_token'] = token_string
        subject.token_string_from_request.should eq token_string
      end

      it 'matches access_token' do
        @request.params['access_token'] = token_string
        subject.token_string_from_request.should eq token_string
      end

      it 'matches oauth_token' do
        @request.params['oauth_token'] = token_string
        subject.token_string_from_request.should eq token_string
      end
    end

    context 'with HTTP_AUTHORIZATION header' do
      it 'matches Bearer' do
        @request.env['HTTP_AUTHORIZATION'] = "Bearer token=#{token_string}"
        subject.token_string_from_request.should eq token_string
      end

      it 'matches OAuth' do
        @request.env['HTTP_AUTHORIZATION'] = "OAuth token=#{token_string}"
        subject.token_string_from_request.should eq token_string
      end

      it 'matches Token' do
        @request.env['HTTP_AUTHORIZATION'] = "Token token=#{token_string}"
        subject.token_string_from_request.should eq token_string
      end
    end
  end

end
