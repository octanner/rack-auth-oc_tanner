require 'spec_helper'

describe Rack::Auth::OCTanner do

  before :each do
    ENV.stub(:[]).with("SCOPES").and_return("public, user.read, user.write, user.delete, admin.read, admin.write, admin.delete")
  end

  subject(:octanner){ Rack::Auth::OCTanner }

  describe '.scopes' do
    subject{ octanner.scopes }
    it{ should be }
    it{ should be_kind_of Rack::Auth::OCTanner::ScopeList }
    its(:size){ should be 7 }
  end

end