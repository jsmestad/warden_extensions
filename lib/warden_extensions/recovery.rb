# Recovery takes care of reseting the user password and send reset instructions
#
# Requirements:
#  Class#reset_password_instructions(object) # method will email user (ActionMailer) and return true/false
#  Class#reset_password_token= # assign reset token. (attr_writer and/or database attribute)
#  Class#reset_password_token  # retrieve reset token. (attr_reader and/or database attribute)
#
# Usage:
#
#   # resets the user password and save the record, true if valid passwords are given, otherwise false
#   User.find(1).reset_password!('password123', 'password123')
#
#   # only resets the user password, without saving the record
#   user = User.find(1)
#   user.reset_password('password123', 'password123')
#
#   # creates a new token and send it with instructions about how to reset the password
#   User.find(1).send_reset_password_instructions

require 'active_support/concern'
require 'active_support/secure_random'

module Warden::Extensions::Recovery
  extend ActiveSupport::Concern

  module ClassMethods

    # Find an initialize a record setting an error if it can't be found.
    def find_or_initialize_with_error_by(attribute, value, error=:invalid) #:nodoc:
      if value.present?
        conditions = { attribute => value }
        record = find(:first, :conditions => conditions)
      end

      unless record
        record = new
        if value.present?
          record.send(:"#{attribute}=", value)
        else
          error = :blank
        end
        record.errors.add(attribute, error)
      end

      record
    end
    
    # Attempt to find a user by it's email. If a record is found, send new
    # password instructions to it. If not user is found, returns a new user
    # with an email not found error.
    # Attributes must contain the user email
    def send_reset_password_instructions(attributes={})
      recoverable = where(:email => attributes[:email]).first
      if recoverable.nil?
        recoverable = new
        recoverable.errors.add(:email, :error)
      end
      recoverable.send_reset_password_instructions if recoverable.persisted?
      recoverable
    end

    # Attempt to find a user by it's reset_password_token to reset it's
    # password. If a user is found, reset it's password and automatically
    # try saving the record. If not user is found, returns a new user
    # containing an error in reset_password_token attribute.
    # Attributes must contain reset_password_token, password and confirmation
    def reset_password_by_token(attributes={})
      recoverable = where(:reset_password_token => attributes[:reset_password_token]).first
      if recoverable.nil?
        recoverable = new
        recoverable.errors.add(:reset_password_token, :error)
      end
      recoverable.reset_password!(attributes[:password], attributes[:password_confirmation]) if recoverable.persisted?
      recoverable
    end

  end

  module InstanceMethods
    # Update password saving the record and clearing token. Returns true if
    # the passwords are valid and the record was saved, false otherwise.
    def reset_password!(new_password, new_password_confirmation)
      self.password = new_password
      self.password_confirmation = new_password_confirmation
      clear_reset_password_token if valid?
      save
    end

    # Resets reset password token and send reset password instructions by email
    def send_reset_password_instructions
      generate_reset_password_token!
      reset_password_instructions(self).deliver
    end
    
    def reset_password_instructions(object)
      raise NotImplementedError unless super
    end

    protected

      # Generates a new random token for reset password
      def generate_reset_password_token
        self.reset_password_token = ActiveSupport::SecureRandom.base64(15).tr('+/=', '-_ ').strip.delete("\n")
      end

      # Resets the reset password token with and save the record without
      # validating
      def generate_reset_password_token!
        generate_reset_password_token && save(:validate => false)
      end

      # Removes reset_password token
      def clear_reset_password_token
        self.reset_password_token = nil
      end
  end

end
