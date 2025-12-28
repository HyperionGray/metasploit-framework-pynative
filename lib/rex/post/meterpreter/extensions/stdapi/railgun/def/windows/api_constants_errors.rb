# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Windows API Constants - ERROR CODES category
# Split from api_constants.rb for better maintainability
#
class DefApiConstants_errors

  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('ERROR_INSTALL_PACKAGE_REJECTED',0x00000659)
    win_const_mgr.add_const('ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE',0x000036C2)
    win_const_mgr.add_const('ERROR_CLIPPING_NOT_SUPPORTED',0x000007D5)
    win_const_mgr.add_const('ERROR_TRANSACTION_REQUEST_NOT_VALID',0x00001A2E)
    win_const_mgr.add_const('ERROR_REDIRECTOR_HAS_OPEN_HANDLES',0x00000702)
    win_const_mgr.add_const('ERROR_SXS_UNTRANSLATABLE_HRESULT',0x000036FD)
    win_const_mgr.add_const('ERROR_INVALID_AT_INTERRUPT_TIME',0x00000068)
    win_const_mgr.add_const('ERROR_USER_PROFILE_LOAD',0x000001F4)
    win_const_mgr.add_const('ERROR_DS_UNWILLING_TO_PERFORM',0x00002035)
    win_const_mgr.add_const('ERROR_MAPPED_ALIGNMENT',0x0000046C)
    win_const_mgr.add_const('ERROR_TM_VOLATILE',0x00001AAC)
    win_const_mgr.add_const('ERROR_DEBUGGER_INACTIVE',0x00000504)
    win_const_mgr.add_const('ERROR_INVALID_LDT_SIZE',0x00000231)
    win_const_mgr.add_const('ERROR_DS_SRC_GUID_MISMATCH',0x00002128)
    win_const_mgr.add_const('ERROR_DS_CANT_CACHE_ATT',0x000020D1)
    win_const_mgr.add_const('ERROR_LOG_FILE_FULL',0x000005DE)
    win_const_mgr.add_const('ERROR_CTX_INVALID_WD',0x00001B89)
    # Note: This is a sample - the full file would contain all ERROR_ constants
  end

end

end; end; end; end; end; end; end