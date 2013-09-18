class Rack::Auth::OCTanner::ScopeList

  # Scopes are defined in the Eve application.  Scopes will
  # typically be compared bit-wise, so it is vital that the
  # list of scopes and the ordinal indexes they are assigned
  # are syncronized everywhere.

  # Eve builds lists of scopes using a left-to-right,
  # "big-endian"-like fashion.  That is, the first scope in
  # the list occupies the far left bit, with the second scope
  # in the list in the second-to-left bit, and so forth building
  # outward to the right.

  # For example, given the following list of scopes:
  #   "public, user.read, user.write, user.delete, admin.read, admin.write, admin.delete"
  #
  # If the "public" and "user.write" scopes were enabled, Eve
  # would produce the following bit field:
  #   "1010000"
  #
  # where "1" denotes the scope is enabled.

  def self.bytes_to_int scopes = ""
    sum = 0
    scopes.to_s.bytes.to_a.reverse.each_with_index { |k, i| sum = sum + (k << (i * 8)) }
    sum
  end

  def initialize scopes = ""
    @scope_string = scopes.to_s
  end

  def size
    return scope_array.size
  end

  # Scopes are indexed left-to-right
  # This matches how the scope bits are produced in the Eve
  # application.  For example,
  def scope_at ordinal
    return scope_array[ordinal]
  end

  def has_scope? scope
    scope_map.has_key? scope
  end

  def index_of scope
    scope_map[scope]
  end

  def scopes_to_int scopes = []
    sum = 0
    scopes.to_a.each do |scope|
      raise Rack::Auth::OCTanner::UndefinedScopeError.new("Undefined scope:  #{scope}") if !has_scope?(scope)
      sum = sum + (1 << index_of(scope))
    end
    sum
  end

  private

  def scope_string
    @scope_string
  end

  def scope_array
    @scope_array = scope_string.split(/[ ,;:]/).map(&:strip).reject(&:empty?).reverse
  end

  def scope_map
    @scope_map = scope_array_to_hash scope_array
  end

  def scope_array_to_hash array
    hash = Hash.new
    array.each_with_index { |k, i| hash[k] = i }
    hash
  end
end