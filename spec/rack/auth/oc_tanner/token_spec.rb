require 'spec_helper'

def make_env(params = {})
  {
    'REQUEST_METHOD' => 'GET',
    'rack.session' => {},
    'rack.input' => StringIO.new('test=true')
  }.merge params
end

describe Rack::Auth::OCTanner::Token do
  let(:app) { lambda { |env| [200, env, []] }}
  let(:logger) { l = ::Logger.new(STDERR); l.level = Logger::FATAL; l } # silence output
  let(:options) {{ key: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", log: logger }}
  let(:token_info) { { 'u' => 'user-id', 's' => "*", 'c' => 'client-id', 'e' => 1234 } }
  let(:token) { SimpleSecrets::Packet.new(options[:key]).pack token_info }
  let(:middleware) { Rack::Auth::OCTanner::Token.new app, options }

  subject{ middleware }

  describe '#initialize' do
    it 'assigns the app variable' do
      subject.instance_variable_get( :@app ).should eq app
    end

    it 'creates a new logger by default' do
      middleware = Rack::Auth::OCTanner::Token.new app, key: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
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
      subject.should_receive(:decode_token).with(token).and_return(token_info)
      response = subject.call(env)
      response[1]['octanner_auth_user'].should eq token_info
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
      decoded_token = token_info.merge({"token" => token, "s" => Rack::Auth::OCTanner::ScopeList.bytes_to_int(token_info['s'])})
      subject.decode_token(token).should eq decoded_token
    end

    it 'returns nil if nothing matches' do
      subject.decode_token('bad1234').should eq nil
    end

    # Real-world example as an integration test
    context 'real-world integration example' do
      let(:options) {{ key: "81ca9f21318178682b924246f3812b99c61cb0a7989efabdd4254589b112ea9a", log: logger }}
      let(:token){ "qPKv_qK10eKNyn-j6AP9B_RAiRW__OzdUlRORlHClLmmPj4Ys74NOpd4RhiGyb_ogFf07gaqryOYPYdAmsncz-IbGhfjqsLtL5S5l7U0vQfl5_aHXwq3AwaPQuSUzfGhabYkvDNl" }
      let(:data){ {"c"=>"eve", "u"=>"my-user", "e"=>55382, "s"=>0b1010000010001000} }

      subject { Rack::Auth::OCTanner::Token.new app, options }

      it 'returns the expected hash data' do
        subject.decode_token(token).should eq data.merge({"token" => token})
      end
    end
  end
end
