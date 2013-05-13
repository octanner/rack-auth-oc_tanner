class Rack::Auth::AuthenticationFilter

  def initialize(scopes = [])
    @required_scopes = Set.new scopes.to_a
  end


  def before(controller)
    controller.head 401 unless authenticate_request(controller.request)
  end


  def after(controller)
  end


  def authenticate_request(request)
    return false unless request

    user_data = request.env['oauth2_token_data']
    return false unless user_data

    authenticate_scopes user_data['scopes']
  end


  def authenticate_scopes(scopes = [])
    @required_scopes.subset? array_to_symbolized_set(scopes.to_a)
  end


  private


  def array_to_symbolized_set(array = [])
    set = Set.new array.map{ |a| a.intern }
  end
end