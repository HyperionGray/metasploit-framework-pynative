#!/usr/bin/env ruby

# Script to analyze Windows API constants and categorize them for splitting

require 'set'

# Read the constants file
constants_file = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
content = File.read(constants_file)

# Extract all constant names
constants = []
content.scan(/win_const_mgr\.add_const\('([^']+)'/) do |match|
  constants << match[0]
end

puts "Total constants found: #{constants.length}"

# Categorize constants by prefix patterns
categories = Hash.new { |h, k| h[k] = [] }

constants.each do |const|
  case const
  when /^ERROR_/
    categories['errors'] << const
  when /^WM_/, /^HWND_/, /^WS_/, /^SW_/, /^SWP_/, /^VK_/, /^IDC_/, /^IDI_/, /^MB_/, /^IDOK/, /^IDCANCEL/, /^IDYES/, /^IDNO/
    categories['ui_windows'] << const
  when /^REG/, /^HKEY_/, /^KEY_/
    categories['registry'] << const
  when /^FILE_/, /^GENERIC_/, /^CREATE_/, /^OPEN_/, /^SHARE_/
    categories['file_io'] << const
  when /^PROCESS_/, /^THREAD_/, /^TOKEN_/, /^SE_/
    categories['process_security'] << const
  when /^SERVICE_/, /^SC_/
    categories['services'] << const
  when /^DNS_/, /^SOCKET_/, /^AF_/, /^SOCK_/, /^IPPROTO_/, /^TCP_/, /^UDP_/, /^IP_/, /^WSAE/
    categories['network'] << const
  when /^CERT_/, /^CRYPT/, /^ALG_/, /^CALG_/, /^PROV_/
    categories['cryptography'] << const
  when /^LANG_/, /^SUBLANG_/, /^SORT_/, /^LOCALE_/
    categories['locale'] << const
  when /^SQL_/, /^ODBC_/
    categories['database'] << const
  when /^PRINTER_/, /^PRINT_/, /^DM_/
    categories['printing'] << const
  when /^MCI_/, /^WAVE_/, /^MIDI_/
    categories['multimedia'] << const
  when /^IMAGE_/, /^PE_/, /^SECTION_/
    categories['pe_format'] << const
  when /^TAPE_/, /^IOCTL_/
    categories['device_io'] << const
  when /^RPC_/, /^NDR_/
    categories['rpc'] << const
  when /^SNMP_/
    categories['snmp'] << const
  when /^HTTP_/, /^INTERNET_/, /^WINHTTP_/
    categories['http_internet'] << const
  when /^SECURITY_/, /^DOMAIN_/, /^POLICY_/
    categories['security_policy'] << const
  else
    categories['misc'] << const
  end
end

# Print categorization results
puts "\nCategorization Results:"
puts "=" * 50

categories.keys.sort.each do |category|
  puts "#{category.upcase}: #{categories[category].length} constants"
end

puts "\nTop 10 categories by size:"
categories.sort_by { |k, v| -v.length }.first(10).each do |category, consts|
  puts "  #{category}: #{consts.length}"
end

# Show some examples from each category
puts "\nExamples from each category:"
categories.keys.sort.each do |category|
  puts "\n#{category.upcase} (#{categories[category].length} total):"
  categories[category].first(5).each do |const|
    puts "  #{const}"
  end
  puts "  ..." if categories[category].length > 5
end