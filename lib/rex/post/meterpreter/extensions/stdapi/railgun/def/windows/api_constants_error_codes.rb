# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants_base'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Windows API Error Code Constants
# Contains ERROR_, DNS_ERROR_, RPC_S_, WSAE, SEC_E_, CRYPT_E_, and other error-related constants
#
class DefApiConstants_ErrorCodes

  #
  # Add error code constants to the manager
  #
  def self.add_constants(win_const_mgr)
    # Windows System Error Codes
    win_const_mgr.add_const('ERROR_INSTALL_PACKAGE_REJECTED', 0x00000659)
    win_const_mgr.add_const('ERROR_DS_SIZELIMIT_EXCEEDED', 0x00002023)
    
    # DNS Error Codes
    win_const_mgr.add_const('DNS_ERROR_INCONSISTENT_ROOT_HINTS', 0x0000255D)
    
    # RPC Error Codes
    win_const_mgr.add_const('RPC_S_ENTRY_TYPE_MISMATCH', 0x00000782)
    
    # Bluetooth Error Codes
    win_const_mgr.add_const('BTH_ERROR_PAIRING_NOT_ALLOWED', 0x00000018)
    win_const_mgr.add_const('BTH_ERROR_QOS_IS_NOT_SUPPORTED', 0x00000027)
    
    # Other Error Codes
    win_const_mgr.add_const('WPWIZ_ERROR_PROV_QI', 0xC0042002)
    win_const_mgr.add_const('MD_WARNING_SAVE_FAILED', 0x000CC809)
  end

end

# Register this constants class with the main loader
DefApiConstants_windows.register_constants(DefApiConstants_ErrorCodes)

end; end; end; end; end; end; end