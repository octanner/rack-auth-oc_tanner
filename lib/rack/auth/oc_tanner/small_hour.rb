class Rack::Auth::OCTanner::SmallHour

  EPOCH_YEAR = 1970

                 #123456789012345678901234
  YEAR_MASK   = 0b11111100000000000000
  MONTH_MASK  = 0b00000011110000000000
  DAY_MASK    = 0b00000000001111100000
  HOUR_MASK   = 0b00000000000000011111

  YEAR_SHIFT = 14
  MONTH_SHIFT = 10
  DAY_SHIFT = 5
  HOUR_SHIFT = 0

  def initialize time = Time.now.utc
    @bits = 0
    shift (time.year - EPOCH_YEAR), YEAR_MASK, YEAR_SHIFT
    shift time.month, MONTH_MASK, MONTH_SHIFT
    shift time.day, DAY_MASK, DAY_SHIFT
    shift time.hour, HOUR_MASK, HOUR_SHIFT
  end

  def to_time
    Time.utc(year, month, day, hour, 0, 0)
  end

  def year
    (unshift YEAR_MASK, YEAR_SHIFT) + EPOCH_YEAR
  end

  def month
    unshift MONTH_MASK, MONTH_SHIFT
  end

  def day
    unshift DAY_MASK, DAY_SHIFT
  end

  def hour
    unshift HOUR_MASK, HOUR_SHIFT
  end

  private

  def unshift bit_mask, bit_shift
    (@bits & bit_mask) >> bit_shift
  end

  def shift value, bit_mask, bit_shift
    @bits = (@bits & ~bit_mask) | (value << bit_shift)
  end
end