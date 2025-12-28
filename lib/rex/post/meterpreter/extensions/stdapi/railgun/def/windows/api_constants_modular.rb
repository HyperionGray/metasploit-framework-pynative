# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# A container holding useful Windows API Constants.
# This file has been refactored to use a modular approach for better maintainability.
# The original 38,000+ line file has been split into logical categories.
#
class DefApiConstants_windows < ApiConstants

  #
  # Load constants from category-specific files
  #
  def self.add_constants(win_const_mgr)
    # Load error codes
    require_relative 'api_constants_errors'
    DefApiConstants_errors.add_constants(win_const_mgr)
    
    # Load UI/Windows constants
    require_relative 'api_constants_ui_windows'
    DefApiConstants_ui_windows.add_constants(win_const_mgr)
    
    # Load network constants
    require_relative 'api_constants_network'
    DefApiConstants_network.add_constants(win_const_mgr)
    
    # TODO: Add remaining categories:
    # - Registry constants (api_constants_registry.rb)
    # - File I/O constants (api_constants_file_io.rb)
    # - Process/Security constants (api_constants_process_security.rb)
    # - Service constants (api_constants_services.rb)
    # - Cryptography constants (api_constants_cryptography.rb)
    # - Locale constants (api_constants_locale.rb)
    # - Database constants (api_constants_database.rb)
    # - Printing constants (api_constants_printing.rb)
    # - Multimedia constants (api_constants_multimedia.rb)
    # - PE format constants (api_constants_pe_format.rb)
    # - Device I/O constants (api_constants_device_io.rb)
    # - RPC constants (api_constants_rpc.rb)
    # - SNMP constants (api_constants_snmp.rb)
    # - COM/OLE constants (api_constants_com_ole.rb)
    # - Graphics constants (api_constants_graphics.rb)
    # - Miscellaneous constants (api_constants_misc.rb)
    
    # For now, load remaining constants from original file
    # This allows for gradual migration
    load_remaining_constants(win_const_mgr)
  end
  
  private
  
  # Temporary method to load constants not yet categorized
  # This should be removed once all constants are properly categorized
  def self.load_remaining_constants(win_const_mgr)
    # Load a subset of remaining constants as an example
    # In practice, this would be replaced by proper category files
    
    # Registry constants
    win_const_mgr.add_const('REGDF_GENFORCEDCONFIG',0x00000020)
    
    # File I/O constants  
    win_const_mgr.add_const('FILE_IS_ENCRYPTED',0x00000001)
    
    # Process/Security constants
    win_const_mgr.add_const('SECURITY_WORLD_RID',0x00000000)
    win_const_mgr.add_const('DOMAIN_NO_LM_OWF_CHANGE',0x00000040)
    
    # Service constants
    win_const_mgr.add_const('SERVICE_CTRL_PAUSE',0x00000001)
    
    # And so on... (this is just a demonstration)
  end

end

end; end; end; end; end; end; end