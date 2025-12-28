#!/usr/bin/env ruby

# Script to extract constants by prefix from the large api_constants.rb file
# This will help us split the file into logical categories

require 'set'

# Read the large constants file
file_path = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
content = File.read(file_path)

# Extract all constant definitions
constants = []
content.scan(/win_const_mgr\.add_const\('([^']+)',\s*([^)]+)\)/) do |name, value|
  constants << [name, value]
end

# Group constants by prefix (first part before underscore or first few characters)
groups = Hash.new { |h, k| h[k] = [] }

constants.each do |name, value|
  # Determine prefix
  prefix = case name
  when /^(ERROR|DNS_ERROR|RPC_S_|WSAE|SEC_E_|CRYPT_E_|SCARD_E_|NTE_E_|TRUST_E_|CERT_E_|OSS_E_|CERTSRV_E_|XENROLL_E_|SPAPI_E_|SETUPAPI_E_)/
    'ERROR_CODES'
  when /^(WM_|BM_|CB_|EM_|LB_|STM_|DM_)/
    'WINDOW_MESSAGES'
  when /^(HWND_|SW_|SWP_|WS_|WS_EX_|CS_|CW_)/
    'WINDOW_MANAGEMENT'
  when /^(HKEY_|REG_|KEY_)/
    'REGISTRY'
  when /^(FILE_|GENERIC_|CREATE_|OPEN_|TRUNCATE_|MOVEFILE_)/
    'FILE_SYSTEM'
  when /^(PROCESS_|THREAD_|TOKEN_|SE_)/
    'PROCESS_THREAD'
  when /^(MCI_|WAVE_|MIDI_|AUX_|MIXER_)/
    'MULTIMEDIA'
  when /^(EVENT_|ETW_)/
    'EVENT_TRACING'
  when /^(CM_|CONFIGRET_|DN_|DIF_)/
    'CONFIG_MANAGER'
  when /^(CERT_|CRYPT_|ALG_|CALG_|PROV_)/
    'CRYPTOGRAPHY'
  when /^(SERVICE_|SC_|SCM_)/
    'SERVICES'
  when /^(SECURITY_|SID_|WELL_KNOWN_)/
    'SECURITY'
  when /^(INTERNET_|HTTP_|FTP_|GOPHER_)/
    'INTERNET'
  when /^(PRINTER_|DRIVER_|JOB_)/
    'PRINTING'
  when /^(LOCALE_|LANG_|SUBLANG_|SORT_)/
    'LOCALE'
  when /^(IMAGE_|SECTION_|PAGE_|MEM_)/
    'MEMORY_IMAGE'
  when /^(SOCKET_|AF_|PF_|SOCK_|IPPROTO_|SO_)/
    'NETWORKING'
  else
    # Group by first part before underscore
    parts = name.split('_')
    if parts.length > 1
      parts[0]
    else
      'MISC'
    end
  end
  
  groups[prefix] << [name, value]
end

# Print statistics
puts "Total constants: #{constants.length}"
puts "Groups found: #{groups.keys.length}"
puts "\nGroup sizes:"
groups.sort_by { |k, v| -v.length }.each do |group, consts|
  puts "  #{group}: #{consts.length} constants"
end

# Save the largest groups to separate files for review
['ERROR_CODES', 'WINDOW_MESSAGES', 'WINDOW_MANAGEMENT', 'REGISTRY', 'FILE_SYSTEM'].each do |group|
  next unless groups[group].any?
  
  filename = "/tmp/constants_#{group.downcase}.txt"
  File.open(filename, 'w') do |f|
    f.puts "# #{group} Constants (#{groups[group].length} total)"
    f.puts
    groups[group].each do |name, value|
      f.puts "win_const_mgr.add_const('#{name}', #{value})"
    end
  end
  puts "Saved #{group} constants to #{filename}"
end