# A Ruby implementation of Small Dates:
#   https://github.com/timshadel/smd
class Rack::Auth::OCTanner::SmD

  MS_PER_SECOND = 1000
  MS_PER_MINUTE = 60 * MS_PER_SECOND
  MS_PER_HOUR = 60 * MS_PER_MINUTE
  DEFAULT_RANGE = (2 ** 16)

  def initialize params = {}
    @range = params[:range] || DEFAULT_RANGE
    @ms_per_unit = params[:ms_per_unit] || MS_PER_HOUR
  end

  def range
    @range
  end

  def range_in_ms
    range * ms_per_unit
  end

  def ms_per_unit
    @ms_per_unit
  end

  def at units
    (units * ms_per_unit) + ((current_ms / range_in_ms).floor * range_in_ms)
  end

  def min
    date (-1 * (range / 2))
  end

  def max
    date (range - 1)
  end

  def date from
    Time.at(at from)
  end

  def from milliseconds
    ((milliseconds % range_in_ms) / ms_per_unit).floor
  end

  def now
    from current_ms
  end

  private

  def current_ms
    Time.now.gmtime.to_i
  end
end