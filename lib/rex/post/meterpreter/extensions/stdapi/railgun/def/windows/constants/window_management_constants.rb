# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

# Windows API Constants - Window Management
class WindowManagementConstants
  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('HWND_BROADCAST',0x00000FFFF)
    win_const_mgr.add_const('WM_SYSCHAR',0x00000106)
    win_const_mgr.add_const('WM_COMPAREITEM',0x00000039)
    win_const_mgr.add_const('WM_QUERYUISTATE',0x00000129)
    # Add more window management constants here...
  end
end

end; end; end; end; end; end; end