require 'spec_helper'

describe Rack::Auth::OCTanner do

  scope_list = ["public", "user.read", "user.write", "user.delete", "admin.read", "admin.write", "admin.delete"]
  before :each do
    allow(ENV).to receive(:[]).with("SCOPES").and_return("public, user.read, user.write, user.delete, admin.read, admin.write, admin.delete")
  end

  subject(:octanner){ Rack::Auth::OCTanner }

  describe '.scopes' do
    subject{ octanner.scopes }
    it{ is_expected.to be }
    it{ is_expected.to be_kind_of Rack::Auth::OCTanner::ScopeList }

    it "should have 7 scopes" do
      expect(subject.size).to be(7)
    end
    context "has scopes" do
      scope_list.each do |scope|
        it "#{scope}" do
          expect(subject.has_scope?(scope)).to be(true)
        end
      end
    end
  end

end