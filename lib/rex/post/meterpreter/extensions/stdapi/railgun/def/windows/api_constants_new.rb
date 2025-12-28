# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'

# Load all category modules
require_relative 'constants/errors'
require_relative 'constants/windows'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# A container holding useful Windows API Constants.
# This class loads constants from multiple category modules.
#
class DefApiConstants_windows < ApiConstants

  #
  # Load constants from all category modules.
  #
  def self.add_constants(win_const_mgr)
    ApiConstantsErrors.add_constants(win_const_mgr)
    ApiConstantsWindows.add_constants(win_const_mgr)
    
    # TODO: Add remaining constants from original file
    # This is a proof of concept - the full implementation will include all categories
    
    # For now, add a few more constants directly to ensure functionality
    win_const_mgr.add_const('MCI_DGV_SETVIDEO_TINT',0x00004003)
    win_const_mgr.add_const('EVENT_TRACE_FLAG_PROCESS',0x00000001)
    win_const_mgr.add_const('TF_LBI_TOOLTIP',0x00000004)
    win_const_mgr.add_const('CM_DRP_CLASSGUID',0x00000009)
    win_const_mgr.add_const('SYMMETRICWRAPKEYBLOB',0x0000000B)
  end

end

end; end; end; end; end; end; end