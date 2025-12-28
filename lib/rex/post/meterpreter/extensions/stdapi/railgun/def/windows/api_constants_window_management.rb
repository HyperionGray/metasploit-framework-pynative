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
# Windows API Window Management Constants
# Contains HWND_, WM_, SW_, SWP_, WS_, and other window-related constants
#
class DefApiConstants_WindowManagement

  #
  # Add window management constants to the manager
  #
  def self.add_constants(win_const_mgr)
    # Window Handle Constants
    win_const_mgr.add_const('HWND_BROADCAST', 0x00000FFFF)
    
    # Window Messages
    win_const_mgr.add_const('WM_SYSCHAR', 0x00000106)
    win_const_mgr.add_const('WM_GETICON', 0x0000007F)
    
    # Window Message Handling
    win_const_mgr.add_const('FLICK_WM_HANDLED_MASK', 0x00000001)
  end

end

# Register this constants class with the main loader
DefApiConstants_windows.register_constants(DefApiConstants_WindowManagement)

end; end; end; end; end; end; end