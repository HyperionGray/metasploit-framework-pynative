# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Windows API Constants - NETWORK category
# Split from api_constants.rb for better maintainability
#
class DefApiConstants_network

  def self.add_constants(win_const_mgr)
    win_const_mgr.add_const('DNS_ERROR_INCONSISTENT_ROOT_HINTS',0x0000255D)
    win_const_mgr.add_const('DNS_TYPE_SINK',0x00000028)
    win_const_mgr.add_const('FD_QOS',0x00000001)
    win_const_mgr.add_const('TCP_CONGESTION_ALGORITHM',0x0000000C)
    win_const_mgr.add_const('DNS_ERROR_ZONE_ALREADY_EXISTS',0x00002589)
    win_const_mgr.add_const('DNS_RTYPE_AXFR',0x00000000)
    win_const_mgr.add_const('INTERNET_HANDLE_TYPE_CONNECT_GOPHER',0x00000003)
    win_const_mgr.add_const('NS_DNS',0x0000000C)
    win_const_mgr.add_const('WINHTTP_OPTION_RESOLVE_TIMEOUT',0x00000002)
    win_const_mgr.add_const('NS_DHCP',0x00000006)
    win_const_mgr.add_const('IP_DEFAULT_MULTICAST_LOOP',0x00000001)
    win_const_mgr.add_const('WINHTTP_QUERY_CONTENT_TYPE',0x00000001)
    win_const_mgr.add_const('FD_WRITE_BIT',0x00000001)
    win_const_mgr.add_const('WINHTTP_CALLBACK_STATUS_FLAG_SECURITY_CHANNEL_ERROR',0x80000000)
    win_const_mgr.add_const('WSA_QOS_EFLOWCOUNT',0x00002B0F)
    win_const_mgr.add_const('DNS_QUERY_NO_HOSTS_FILE',0x00000040)
    win_const_mgr.add_const('HTTP_LOGGING_FLAG_LOCAL_TIME_ROLLOVER',0x00000001)
    win_const_mgr.add_const('DNS_ERROR_RCODE_NOTAUTH',0x00002331)
    win_const_mgr.add_const('WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE',0x00020000)
    win_const_mgr.add_const('WSAESOCKTNOSUPPORT',0x0000273C)
    win_const_mgr.add_const('NS_NIS',0x00000029)
    win_const_mgr.add_const('HTTP_LOG_FIELD_SERVER_IP',0x00000040)
    # Note: This is a sample - the full file would contain all network-related constants
  end

end

end; end; end; end; end; end; end