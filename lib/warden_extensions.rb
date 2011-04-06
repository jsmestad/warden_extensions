# This is a base file that only autoloads modules on invocation 
# See lib/warden_extensions/*.rb for the module specific code

module Warden
  module Extensions
    
    # Establish the namespace that all modules will use
    
    autoload :Recovery, 'warden_extensions/recovery'
    autoload :Authentication, 'warden_extensions/authentication'

  end
end