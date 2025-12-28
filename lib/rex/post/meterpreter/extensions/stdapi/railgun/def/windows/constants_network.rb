# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

# Network and DNS constants for Windows API
class NetworkConstants
  def self.add_constants(win_const_mgr)
    # DNS constants
    win_const_mgr.add_const('DNS_TYPE_SINK',0x00000028)
    win_const_mgr.add_const('DNS_RTYPE_AXFR',0x00000000)
    # Add more DNS_, FD_ constants here...
  end
end

end; end; end; end; end; end; end