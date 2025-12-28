# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

# Error constants for Windows API
class ErrorConstants
  def self.add_constants(win_const_mgr)
    # Error codes
    win_const_mgr.add_const('ERROR_INSTALL_PACKAGE_REJECTED',0x00000659)
    win_const_mgr.add_const('ERROR_SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE',0x000036C2)
    # Add more ERROR_ constants here...
  end
end

end; end; end; end; end; end; end