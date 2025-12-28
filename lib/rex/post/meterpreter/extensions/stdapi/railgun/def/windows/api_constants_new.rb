# -*- coding: binary -*-
require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/index'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# A container holding useful Windows API Constants.
# This version loads constants from categorized files for better maintainability.
# 
# The original 38,209-line file has been split into logical categories:
# - errors.rb: Error codes and exception constants
# - windows_messages.rb: Windows message constants (WM_*, BM_*, etc.)
# - virtual_keys.rb: Virtual key codes (VK_*)
# - And more categories as needed
#
class DefApiConstants_windows < ApiConstants

  #
  # Load constants from all categorized files.
  #
  def self.add_constants(win_const_mgr)
    DefApiConstantsIndex.add_constants(win_const_mgr)
  end

end

end; end; end; end; end; end; end