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
# Virtual key codes
#
class DefApiConstantsVirtualKeys < ApiConstants

  #
  # Add virtual key constants
  #
  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('VK_TAB',0x00000009)
    win_const_mgr.add_const('VK_LBUTTON',0x00000001)
    # Add more VK_ constants here...
  end

end

end; end; end; end; end; end; end