# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Windows API Constants - UI/WINDOWS category
# Split from api_constants.rb for better maintainability
#
class DefApiConstants_ui_windows

  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('WM_SYSCHAR',0x00000106)
    win_const_mgr.add_const('WM_COMPAREITEM',0x00000039)
    win_const_mgr.add_const('VK_TAB',0x00000009)
    win_const_mgr.add_const('VK_LBUTTON',0x00000001)
    win_const_mgr.add_const('CB_GETEDITSEL',0x00000140)
    win_const_mgr.add_const('SWP_NOZORDER',0x00000004)
    win_const_mgr.add_const('WM_QUERYUISTATE',0x00000129)
    win_const_mgr.add_const('LB_SELITEMRANGEEX',0x00000183)
    win_const_mgr.add_const('TBS_LEFT',0x00000004)
    # Note: This is a sample - the full file would contain all UI/Windows constants
  end

end

end; end; end; end; end; end; end