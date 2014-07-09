require 'spec_helper'

describe Rack::Auth::OCTanner::AuthenticationFilter do

  let(:scope_string){ "public, user.read, user.write, user.delete, admin.read, admin.write, admin.delete" }
  let(:scope_list){ Rack::Auth::OCTanner::ScopeList.new scope_string }

  before :each do
    Rack::Auth::OCTanner.stub(:scopes).and_return{ scope_list }
  end

  let(:token_info) { { "c" => "eve", "u" => "my-user", "e" => 383, "s" => "\xA0\x88" } }

  let(:response_ok){ { status: 200, body: token_info.to_json } }
  let(:response_unauthorized){ { status: 401 } }

  let(:smd){ SmD::SmD.new }

  describe '#initialize' do
    it 'defaults to no scopes' do
      subject.instance_variable_get(:@required_scopes).should eq 0
    end

    it 'accepts nil for no scopes' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new nil
      filter.instance_variable_get(:@required_scopes).should eq 0
    end

    it 'accepts an array of scope values' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new [ "public", "user.write", "admin.read" ]
      filter.instance_variable_get(:@required_scopes).should eq 0b1010100
    end

    it 'accepts an empty array' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new []
      filter.instance_variable_get(:@required_scopes).should eq 0
    end

    it 'raises an error if a required scope is not defined in the global list' do
      expect{ Rack::Auth::OCTanner::AuthenticationFilter.new(['foobar']) }.to raise_error(Rack::Auth::OCTanner::UndefinedScopeError)
    end
  end


  describe '#before' do
    it 'calls controller.head(401) when authentication fails' do
      controller = double('controller', request: nil)
      controller.should_receive(:head).with(401)
      subject.before(controller)
    end
  end


  describe '#authenticate_request' do

    before :each do
      @request = OpenStruct.new
      @request.params = {}
      @request.env = {}
    end

    it 'should return true if authentication succeeds' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new
      Rack::Auth::OCTanner::AuthenticationFilter.any_instance.stub(:authenticate_scopes).and_return(true)
      Rack::Auth::OCTanner::AuthenticationFilter.any_instance.stub(:expired?).and_return(false)
      @request.env['octanner_auth_user'] = token_info
      subject.authenticate_request(@request).should be true
    end

    it 'tries to authenticate scopes' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new
      filter.should_receive(:authenticate_scopes).once
      @request.env['octanner_auth_user'] = token_info
      filter.authenticate_request(@request)
    end

    it 'tries to authenticate expiration' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new
      Rack::Auth::OCTanner::AuthenticationFilter.any_instance.stub(:authenticate_scopes).and_return(true)
      filter.should_receive(:expired?).once
      @request.env['octanner_auth_user'] = token_info
      filter.authenticate_request(@request)
    end

    context 'authentication failures' do
      it 'should return false if no request' do
        subject.authenticate_request(nil).should be false
      end

      it 'should return false if no token data' do
        subject.authenticate_request(@request).should be false
      end
    end
  end


  describe '#authenticate_scopes' do
    it 'returns true if no scopes are required' do
      subject.authenticate_scopes(0b1010100).should eq true
    end

    it 'returns true if all required scopes are included' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new [ "public", "user.write", "admin.read" ]
      filter.authenticate_scopes(0b1010100).should eq true
    end

    it 'returns false if only some required scopes are included' do
      filter = Rack::Auth::OCTanner::AuthenticationFilter.new [ "public", "user.write", "admin.read" ]
      filter.authenticate_scopes(0b1000000).should eq false
    end
  end


  describe "#expired?" do
    let(:token_smd){ 300 }

    context "invalid inputs" do
      context "smd is nil" do
        it "is expired if token smd is nil" do
          subject.expired?(nil).should eq true
        end

        it "is expired if test smd is nil" do
          subject.expired?(1, nil).should eq true
        end
      end

      context "smd is out of range" do
        it "is expired if token smd is negative" do
          subject.expired?(-1).should eq true
        end

        it "is expired if token smd exceeds SmD range" do
          subject.expired?(smd.range + 1).should eq true
        end

        it "is expired if test smd is negative" do
          subject.expired?(1, -1).should eq true
        end

        it "is expired if test smd exceeds SmD range" do
          subject.expired?(1, smd.range + 1).should eq true
        end
      end
    end


    # The SmD design is based on ranges of units.  After the
    # last unit in a range, the range rolls-over to the first
    # unit in the same range.  This is unfortunate when doing
    # comparisons of times, because it is possible that one
    # time will be in one range and the other time will be in
    # the next range.  (TODO: Some other way we can do this?)
    #
    # There are are four conditions to check:
    #   1. Times are both in the "main SmD range"
    #   2. Times straddle the "next range buffer" condition
    #   3. Times are both in the "next range buffer" condition
    #   4. Times straddle range rollover boundaries
    #
    # Each condition includes three tests:
    #   1. Token time is after test time - Not expired
    #   2. Token time is equal to test time - Expired
    #   3. Token time is before to test time - Expired
    #
    # And one more for the #4 condition:
    #   1. Token time after range rollover with test time before the buffer - Expired
    #
    # This last one is the tricky assumption; we only accept tokens that appear
    # to be in the "next range" when the test time is withing the "rollover buffer".
    # Otherwise, we assume the token is expired.  We have to do this to avoid
    # a years-old-token from being accepted, except in this limited period of time
    # where we can't really be sure it's invalid.

    # November 10th, 2014 is a SmD rollover date for default configuration
    let(:rollover_date){ Time.utc(2014, 11, 10) }
    let(:rollover_smd){ smd.from (rollover_date.to_i * 1000) }
    let(:rollover_buffer_start){ rollover_date - (Rack::Auth::OCTanner::AuthenticationFilter::SMD_ROLLOVER_BUFFER_DAYS * 24 * 60 * 60) }
    let(:rollover_buffer_start_smd){ smd.from (rollover_buffer_start.to_i * 1000) }

    describe "Token expiration validation" do
      context "when test time & token time before rollover buffer start" do
        it "a token after test is not expired" do
          subject.expired?(
            rollover_buffer_start_smd - 1,
            rollover_buffer_start_smd - 2
          ).should eq false
        end

        it "a token equal to test is expired" do
          subject.expired?(
            rollover_buffer_start_smd - 1,
            rollover_buffer_start_smd - 1
          ).should eq true
        end

        it "a token before test is expired" do
          subject.expired?(
            rollover_buffer_start_smd - 2,
            rollover_buffer_start_smd - 1
          ).should eq true
        end
      end

      context "when test time & token time straddle the rollover buffer start" do
        it "a token after test is not expired" do
          subject.expired?(
            rollover_buffer_start_smd + 1,
            rollover_buffer_start_smd - 1
          ).should eq false
        end

        it "a token equal to test is expired" do
          subject.expired?(
            rollover_buffer_start_smd,
            rollover_buffer_start_smd
          ).should eq true
        end

        it "a token before test is expired" do
          subject.expired?(
            rollover_buffer_start_smd - 1,
            rollover_buffer_start_smd + 1
          ).should eq true
        end
      end

      context "when test time & token time are within the rollover buffer start" do
        it "a token after test is not expired" do
          subject.expired?(
            rollover_buffer_start_smd + 2,
            rollover_buffer_start_smd + 1
          ).should eq false
        end

        it "a token equal to test is expired" do
          subject.expired?(
            rollover_buffer_start_smd + 1,
            rollover_buffer_start_smd + 1
          ).should eq true
        end

        it "a token before test is expired" do
          subject.expired?(
            rollover_buffer_start_smd + 1,
            rollover_buffer_start_smd + 2
          ).should eq true
        end
      end

      context "when test time & token time straddle the rollover" do
        it "a token after test is not expired" do
          subject.expired?(
            1,
            smd.range - 1
          ).should eq false
        end

        it "a token equal to test is expired" do
          subject.expired?(
            0,
            0
          ).should eq true
        end

        it "a day-less-than-year-long token after test is not expired" do
          subject.expired?(
            ((smd.range - 2) + (365 * 24)) % smd.range,
            smd.range - 1
          ).should eq false
        end

        it "a year-long token after test is not expired" do
          subject.expired?(
            ((smd.range - 1) + (365 * 24)) % smd.range,
            smd.range - 1
          ).should eq false
        end

        it "a year-and-a-day-long token after test is expired" do
          subject.expired?(
            ((smd.range - 1) + (365 * 24) + 1) % smd.range,
            smd.range - 1
          ).should eq true
        end
      end
    end
  end
end