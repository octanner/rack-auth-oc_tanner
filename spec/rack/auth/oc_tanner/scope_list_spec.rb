require 'spec_helper'

describe Rack::Auth::OCTanner::ScopeList do

  let(:scope_string){ "public user.read, user.write; user.delete: admin.read, admin.write, admin.delete" }

  subject(:scope_list){ Rack::Auth::OCTanner::ScopeList.new scope_string }

  describe '.bytes_to_int' do
    it 'converts the scope bytes to an integer' do
      bytes = "\xA0\x88"
      i = Rack::Auth::OCTanner::ScopeList.bytes_to_int bytes
      expect(i).to eq 0b1010000010001000
      expect(i.to_s(2)).to eq bytes.unpack('B*').first
    end
  end

  describe '#size' do
    it 'returns the number of scopes loaded' do
      expect(scope_list.size).to eq 7
    end
  end

  describe'#scope_at' do
    it 'returns the scope for the given ordinal' do
      expect(scope_list.scope_at(4)).to eq 'user.write'
    end

    it 'returns nil if the ordinal is out of range' do
      expect(scope_list.scope_at(999)).to be_nil
    end
  end

  describe'#has_scope?' do
    it 'returns true if it has the scope' do
      expect(scope_list.has_scope?('user.delete')).to eq true
    end

    it 'returns false if it does not have the scope' do
      expect(scope_list.has_scope?('foo.bar')).to eq false
    end
  end

  describe '#index_of' do
    it 'returns the ordinal for the given scope' do
      expect(scope_list.index_of('user.write')).to eq 4
    end

    it 'returns nil if it does not have the scope' do
      expect(scope_list.index_of('foo.bar')).to eq nil
    end
  end

  describe '#scopes_to_int' do
    it 'returns an left-to-right bitwise ordinal sum for the given scopes' do
      expect(scope_list.scopes_to_int(['public', 'user.write', 'admin.read'])).to eq 0b1010100
    end

    it 'returns zero if no scopes given' do
      expect(scope_list.scopes_to_int([])).to eq 0
    end

    it 'returns zero if nil scopes given' do
      expect(scope_list.scopes_to_int(nil)).to eq 0
    end

    it 'raises error if a given scope does not exist' do
      expect{ scope_list.scopes_to_int(['foobar']) }.to raise_error(Rack::Auth::OCTanner::UndefinedScopeError)
    end
  end
end