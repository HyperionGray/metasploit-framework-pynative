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
# Error codes and exception constants
#
class DefApiConstantsErrors < ApiConstants

  #
  # Add error constants
  #
  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('ERROR_INSTALL_PACKAGE_REJECTED',0x00000659)
    win_const_mgr.add_const('ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE',0x000036C2)
    win_const_mgr.add_const('ERROR_DS_SIZELIMIT_EXCEEDED',0x00002023)
    win_const_mgr.add_const('ERROR_REDIRECTOR_HAS_OPEN_HANDLES',0x00000702)
    win_const_mgr.add_const('ERROR_CLIPPING_NOT_SUPPORTED',0x000007D5)
    win_const_mgr.add_const('ERROR_TRANSACTION_REQUEST_NOT_VALID',0x00001A2E)
    win_const_mgr.add_const('ERROR_DS_SRC_GUID_MISMATCH',0x00002128)
    win_const_mgr.add_const('ERROR_DS_CANT_CACHE_ATT',0x000020D1)
    win_const_mgr.add_const('ERROR_LOG_FILE_FULL',0x000005DE)
    win_const_mgr.add_const('ERROR_CTX_INVALID_WD',0x00001B89)
    win_const_mgr.add_const('ERROR_SXS_UNTRANSLATABLE_HRESULT',0x000036FD)
    win_const_mgr.add_const('ERROR_INVALID_AT_INTERRUPT_TIME',0x00000068)
    win_const_mgr.add_const('EXCEPTION_MAXIMUM_PARAMETERS',0x0000000F)
  end

end

end; end; end; end; end; end; end