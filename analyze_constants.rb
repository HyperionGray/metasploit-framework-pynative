#!/usr/bin/env ruby

# Script to analyze Windows API constants and categorize them
require 'set'

def analyze_constants(file_path)
  constants = []
  categories = Hash.new { |h, k| h[k] = [] }
  
  File.readlines(file_path).each do |line|
    if line.match(/win_const_mgr\.add_const\('([^']+)',/)
      const_name = $1
      constants << const_name
      
      # Categorize by prefix patterns
      case const_name
      when /^(HWND_|WM_|WS_|SW_|SWP_|SHOW_|WINDOW_)/
        categories['window_management'] << const_name
      when /^(ERROR_|NERR_|DNS_ERROR_|RPC_S_|SEC_E_)/
        categories['error_codes'] << const_name
      when /^(REG|HKEY_|KEY_|CM_|CONFIGFLAG_)/
        categories['registry_config'] << const_name
      when /^(FILE_|GENERIC_|CREATE_|OPEN_|SHARE_|SECURITY_)/
        categories['file_security'] << const_name
      when /^(PROCESS_|THREAD_|TOKEN_|SE_|PRIVILEGE_)/
        categories['process_security'] << const_name
      when /^(DNS_|NS_|WSAE|AF_|PF_|SOCK_|IPPROTO_)/
        categories['network_dns'] << const_name
      when /^(CERT_|CRYPT_|ALG_|CALG_|PROV_|CMSG_)/
        categories['crypto_certificates'] << const_name
      when /^(MCI_|WAVE_|MIXER_|MM_|MIDI_)/
        categories['multimedia'] << const_name
      when /^(SERVICE_|SC_|SERVICES_)/
        categories['services'] << const_name
      when /^(EVENT_|EVENTLOG_|TRACE_)/
        categories['events_logging'] << const_name
      when /^(PRINTER_|DRIVER_|DM_|DEVMODE_)/
        categories['printing'] << const_name
      when /^(LANG_|SUBLANG_|LOCALE_|CP_)/
        categories['locale_language'] << const_name
      when /^(IMAGE_|PE_|SECTION_|RELOC_)/
        categories['pe_image'] << const_name
      when /^(DEVICE_|IOCTL_|CTL_CODE)/
        categories['device_io'] << const_name
      when /^(TRUSTEE_|ACCESS_|AUDIT_|ACE_)/
        categories['access_control'] << const_name
      else
        categories['miscellaneous'] << const_name
      end
    end
  end
  
  puts "Total constants: #{constants.length}"
  puts "\nCategory breakdown:"
  categories.each do |category, consts|
    puts "#{category}: #{consts.length} constants"
  end
  
  # Show sample constants from each category
  puts "\nSample constants by category:"
  categories.each do |category, consts|
    puts "\n#{category.upcase}:"
    consts.first(5).each { |c| puts "  #{c}" }
    puts "  ..." if consts.length > 5
  end
  
  categories
end

if __FILE__ == $0
  file_path = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
  analyze_constants(file_path)
end