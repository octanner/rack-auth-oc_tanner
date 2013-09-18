class HelloController < ApplicationController

  before_filter Rack::Auth::OCTanner::AuthenticationFilter.new(), only: :hello

  def hi
    render json: { message: "Hi!" }
  end

  def hello
    user = env['octanner_auth_user']['u']
    render json: { message: "Hello there, #{user}!" }
  end
end
