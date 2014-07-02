require 'smd'

class Rack::Auth::OCTanner::AuthenticationFilter

  SMD_ROLLOVER_BUFFER_DAYS = 131  # Roughly until November 10th; adjust downward accordingly

  def initialize(scopes = [])
    @required_scopes = Rack::Auth::OCTanner.scopes.scopes_to_int scopes
  end

  def before(controller)
    controller.head 401 unless authenticate_request(controller.request)
  end

  def after(controller)
  end

  def authenticate_request(request)
    return false unless request

    token_data = request.env['octanner_auth_user']
    return false unless token_data

    authenticate_scopes(token_data['s']) && !expired?(token_data['e'])
  end

  def authenticate_scopes(scopes = 0)
    required_scopes & scopes == required_scopes
  end

  # Returns true if the token is expired
  #
  # Generally, a token is expired if the token's expiration time is
  # less than or equal to the current time.
  #
  # Due to how SmD is designed, this won't work if the current
  # time is near a SmD rollover boundary and the token's expiration
  # time is in the next boundary.  In this case, the times are
  # normalized into the same SmD range and retested.
  #
  # For example, with SmD defaults, there is a range rollover boundary
  # on "2014-11-10 00:00:00 UTC" (SmD = 65536).  A token with an expiration
  # time of "2014-11-10 03:00:00 UTC" (SmD = 3) will fail when checked
  # against a expiration time between "2007-05-20 11:00:00 UTC" (SmD = 3)
  # and "2014-11-10 00:00:00 UTC" (SmD = 65536), because SmD = 3 will
  # be interpreted as "2007-05-20 11:00:00 UTC" and not "2014-11-10 03:00:00 UTC".
  def expired?(token_smd, test_smd = time_to_smd(Time.now))
    return true if !valid_smd? token_smd
    return true if !valid_smd? test_smd

    return true if is_in_rollover_buffer?(token_smd) && test_smd <= ((token_smd + smd_rollover_buffer) % small_date.range)
    return false if token_smd > test_smd
    return false if is_in_rollover_buffer?(test_smd) && token_smd <= ((test_smd + smd_rollover_buffer) % small_date.range)

    true
  end

  private

  # Returns the buffer accounting for SmD rollover handling, in SmD block format
  def smd_rollover_buffer
    @smd_rollover_buffer ||= (SMD_ROLLOVER_BUFFER_DAYS * 24 * SmD::SmD::MS_PER_HOUR) / small_date.ms_per_unit
  end

  def required_scopes
    @required_scopes
  end

  def small_date
    @smd ||= SmD::SmD.new
  end

  # Returns the the given time in a SmD format.
  def time_to_smd time
    small_date.from(time.gmtime.to_i * 1000)
  end

  def valid_smd? smd
    return false if smd.nil?
    return false if smd < 0
    return false if smd > small_date.range
    true
  end

  # Returns true if the given SmD is within the rollover buffer
  def is_in_rollover_buffer? smd
    return true if smd + smd_rollover_buffer > small_date.range
    false
  end
end