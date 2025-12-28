# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

# Window and UI constants for Windows API
class WindowConstants
  def self.add_constants(win_const_mgr)
    # Window constants
    win_const_mgr.add_const('HWND_BROADCAST',0x00000FFFF)
    win_const_mgr.add_const('WM_COMPAREITEM',0x00000039)
    # Add more WM_, HWND_ constants here...
  end
end

end; end; end; end; end; end; end