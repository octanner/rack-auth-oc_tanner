require 'spec_helper'

describe Rack::Auth::OCTanner::ScopeList do

  let(:scope_string){ "public user.read, user.write; user.delete: admin.read, admin.write, admin.delete" }

  subject(:scope_list){ Rack::Auth::OCTanner::ScopeList.new scope_string }

  describe '.bytes_to_int' do
    it 'converts the scope bytes to an integer' do
      bytes = "\xA0\x88"
      i = Rack::Auth::OCTanner::ScopeList.bytes_to_int bytes
      i.should eq 0b1010000010001000
      i.to_s(2).should eq bytes.unpack('B*').first
    end
  end

  describe '#size' do
    it 'returns the number of scopes loaded' do
      scope_list.size.should eq 7
    end
  end

  describe'#scope_at' do
    it 'returns the scope for the given ordinal' do
      scope_list.scope_at(4).should eq 'user.write'
    end

    it 'returns nil if the ordinal is out of range' do
      scope_list.scope_at(999).should be_nil
    end
  end

  describe'#has_scope?' do
    it 'returns true if it has the scope' do
      scope_list.has_scope?('user.delete').should be_true
    end

    it 'returns false if it does not have the scope' do
      scope_list.has_scope?('foo.bar').should be_false
    end
  end

  describe '#index_of' do
    it 'returns the ordinal for the given scope' do
      scope_list.index_of('user.write').should eq 4
    end

    it 'returns nil if it does not have the scope' do
      scope_list.index_of('foo.bar').should be_false
    end
  end

  describe '#scopes_to_int' do
    it 'returns an left-to-right bitwise ordinal sum for the given scopes' do
      scope_list.scopes_to_int(['public', 'user.write', 'admin.read']).should eq 0b1010100
    end

    it 'returns zero if no scopes given' do
      scope_list.scopes_to_int([]).should eq 0
    end

    it 'returns zero if nil scopes given' do
      scope_list.scopes_to_int(nil).should eq 0
    end

    it 'raises error if a given scope does not exist' do
      expect{ scope_list.scopes_to_int(['foobar']) }.to raise_error(Rack::Auth::OCTanner::UndefinedScopeError)
    end
  end
end