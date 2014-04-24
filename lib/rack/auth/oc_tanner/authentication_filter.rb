require 'smd'

class Rack::Auth::OCTanner::AuthenticationFilter

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

  def expired?(token_smd, expiration_smd = time_to_smd(Time.now))
    return true if token_smd.nil?

    return false if token_smd > expiration_smd

    true
  end

  private

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
end