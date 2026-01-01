# -*- coding: binary -*-

# Auto-generated index file for Windows API constants
# This file loads all constant categories

require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/errors'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/windows_messages'
require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/virtual_keys'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Loads all Windows API constants from categorized files
#
class DefApiConstantsIndex
  def self.add_constants(win_const_mgr)
    DefApiConstantsErrors.add_constants(win_const_mgr)
    DefApiConstantsWindowsMessages.add_constants(win_const_mgr)
    DefApiConstantsVirtualKeys.add_constants(win_const_mgr)
  end
end

end; end; end; end; end; end; end