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

    authenticate_scopes(token_data['s']) && authenticate_expires(token_data['e'])
  end

  def authenticate_scopes(scopes = 0)
    required_scopes & scopes == required_scopes
  end

  # Uses SmD date from the token to determine if the token
  # has "expired".  See:  https://npmjs.org/package/smd
  # NOTE: There are some issues when a token date is on the
  # SmD range "boundary"; Tim will resolve those and we'll
  # implement here.
  def authenticate_expires(smd, current_time = Time.now.gmtime)
    return true if small_date.date(smd) > current_time
    false
  end

  private

  def required_scopes
    @required_scopes
  end

  def small_date
    @smd ||= Rack::Auth::OCTanner::SmD.new
  end
end