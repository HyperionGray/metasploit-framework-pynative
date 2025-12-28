# -*- coding: binary -*-
# Window Messages and UI Constants
# This file contains Windows UI and window message constants

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

module ApiConstantsWindows
  def self.add_constants(win_const_mgr)
    # Sample window constants - these will be populated by the splitting script
    win_const_mgr.add_const('HWND_BROADCAST',0x00000FFFF)
    win_const_mgr.add_const('WM_CONVERTREQUEST',0x0000010A)
    win_const_mgr.add_const('WM_QUERYUISTATE',0x00000129)
    win_const_mgr.add_const('WM_SYSCHAR',0x00000106)
  end
end

end; end; end; end; end; end; end