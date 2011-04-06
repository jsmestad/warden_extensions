# Standard Authentication module with basic audit trail attributes
#
# Instance Attributes:
#   email                 # This is used as the username as well
#   encrypted_password    # stores the bcrypt encrypted password
#   last_sign_in_at       # timestamp of the last session
#   current_sign_in_at    # timestamp of the current session
#   last_sign_in_ip       # ip address of the last session
#   current_sign_in_ip    # ip address of the current session
#   sign_in_count         # total number of sessions
#

require 'active_support/concern'
require 'bcrypt'

module Warden::Extensions::Authentication
  extend ActiveSupport::Concern

  included do
    attr_reader :password, :current_password

    attr_accessor :password_confirmation

    validates :email, :presence => true, :uniqueness => {:case_sensitive => false}, :format => /^([\w\.%\+\-]+)@([\w\-]+\.)+([\w]{2,})$/i
    validates :password, :presence => true, :length => 6..20, :confirmation => true, :if => :password_required?
  end

  module ClassMethods

    # Gererates a default password digest based on stretches, salt, pepper and the
    # incoming password. We don't strech it ourselves since BCrypt does so internally.
    def digest(password, salt)
      ::BCrypt::Engine.hash_secret(password, salt, 10)
    end

    def salt
      ::BCrypt::Engine.generate_salt
    end

  end

  module InstanceMethods

    # Regenerates password salt and encrypted password each time password is set,
    # and then trigger any "after_changed_password"-callbacks.
    def password=(new_password)
      @password = new_password

      if @password.present?
        self.password_salt = self.class.salt
        self.encrypted_password = password_digest(@password)
      end
    end

    # Verifies whether an incoming_password (ie from sign in) is the user password.
    def valid_password?(incoming_password)
      password_digest(incoming_password) == self.encrypted_password
    end

    # Update record attributes when :current_password matches, otherwise returns
    # error on :current_password. It also automatically rejects :password and
    # :password_confirmation if they are blank.
    def update_with_password(params={})
      current_password = params.delete(:current_password)

      if params[:password].blank?
        params.delete(:password)
        params.delete(:password_confirmation) if params[:password_confirmation].blank?
      end

      result = if valid_password?(current_password)
                 update_attributes(params)
               else
                 self.errors.add(:current_password, current_password.blank? ? :blank : :invalid)
                 self.attributes = params
                 false
               end

      clean_up_passwords
      result
    end


    def timed_out?(last_access)
      last_access && last_access <= 30.minutes.ago
    end

    def update_tracked_fields!(request)
      old_current, new_current = self.current_sign_in_at, Time.now
      self.last_sign_in_at     = old_current || new_current
      self.current_sign_in_at  = new_current

      old_current, new_current = self.current_sign_in_ip, request.remote_ip
      self.last_sign_in_ip     = old_current || new_current
      self.current_sign_in_ip  = new_current

      self.sign_in_count ||= 0
      self.sign_in_count += 1

      if new_record?
        save
      else
        save(:validate => false)
      end
    end

    def clean_up_passwords
      self.password = self.password_confirmation = nil
    end

    protected

      def password_required?
        !persisted? || !password.nil? || !password_confirmation.nil?
      end

      def password_digest(password)
        self.class.digest(password, self.password_salt)
      end

  end

end