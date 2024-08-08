class ExCurrentUserProvider < Auth::DefaultCurrentUserProvider
  TOKEN_COOKIX ||= "logged_in".freeze

  def log_on_user(user, session, cookies, opts = {})
    super
    require 'openssl' if !defined?(OpenSSL)
    require 'base64' if !defined?(Base64)
    payload = { username: user.username, user_id: user.id, avatar: user.avatar_template, group: user.title }
    payload_sha = Digest::SHA256.hexdigest payload.to_json
    hash_function = OpenSSL::Digest.new('sha256')
    hmac = OpenSSL::HMAC.hexdigest(hash_function, SiteSetting.cookie_ui_key, payload_sha)
    payload[:hmac] = hmac
    token = Base64.strict_encode64(payload.to_json)
    cookies.permanent[TOKEN_COOKIX] = { value: token, httponly: true, domain: :all }
  end
  
  def log_off_user(session, cookies)
    super
    cookies[TOKEN_COOKIX] = { value: '', httponly: true, domain: :all }
  end

  def refresh_session(user, session, cookie_jar)
    super

    if user && @user_token && @user_token.user == user
      if user_data_changed?(user, session)
        update_auth_cookie!(user, cookie_jar)
        update_session_user_data(user, session)
      end
    end
  end

  private

  def user_data_changed?(user, session)
    return true if session[:user_data].nil?

    current_data = user_data_hash(user)
    session[:user_data] != current_data
  end

  def user_data_hash(user)
    Digest::MD5.hexdigest("#{user.username}#{user.avatar_template}#{user.title}")
  end

  def update_session_user_data(user, session)
    session[:user_data] = user_data_hash(user)
  end

  def update_auth_cookie!(user, cookie_jar)
    payload = {
      username: user.username,
      user_id: user.id,
      avatar: user.avatar_template,
      group: user.title
    }
    payload_sha = Digest::SHA256.hexdigest payload.to_json
    hash_function = OpenSSL::Digest.new('sha256')
    hmac = OpenSSL::HMAC.hexdigest(hash_function, SiteSetting.cookie_ui_key, payload_sha)
    payload[:hmac] = hmac
    token = Base64.strict_encode64(payload.to_json)
    
    cookie_jar.permanent[TOKEN_COOKIX] = { value: token, httponly: true, domain: :all }
  end
end