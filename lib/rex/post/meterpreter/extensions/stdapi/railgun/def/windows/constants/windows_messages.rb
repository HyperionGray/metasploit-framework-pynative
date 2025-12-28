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
# Windows message constants (WM_*, BM_*, etc.)
#
class DefApiConstantsWindowsMessages < ApiConstants

  #
  # Add Windows message constants
  #
  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('WM_SYSCHAR',0x00000106)
    win_const_mgr.add_const('WM_GETICON',0x0000007F)
    win_const_mgr.add_const('WM_QUERYUISTATE',0x00000129)
    win_const_mgr.add_const('WM_COMPAREITEM',0x00000039)
    # Add more WM_ constants here...
  end

end

end; end; end; end; end; end; end