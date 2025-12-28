# -*- coding: binary -*-
# Windows Error Codes and Status Values
# This file contains Windows error constants

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

module ApiConstantsErrors
  def self.add_constants(win_const_mgr)
    # Sample error constants - these will be populated by the splitting script
    win_const_mgr.add_const('ERROR_INSTALL_PACKAGE_REJECTED',0x00000659)
    win_const_mgr.add_const('ERROR_INVALID_MONITOR_HANDLE',0x000005B5)
    win_const_mgr.add_const('ERROR_TRANSLATION_COMPLETE',0x000002F5)
    win_const_mgr.add_const('ERROR_REPARSE_TAG_INVALID',0x00001129)
  end
end

end; end; end; end; end; end; end