#!/usr/bin/env ruby

# Script to analyze Windows API constants and categorize them for splitting

require 'set'

# Read the constants file
constants_file = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
content = File.read(constants_file)

# Extract all constant names and values
constants = []
content.scan(/win_const_mgr\.add_const\('([^']+)',([^)]+)\)/) do |match|
  constants << { name: match[0], value: match[1] }
end

puts "Total constants found: #{constants.length}"

# Categorize constants by prefix patterns
categories = Hash.new { |h, k| h[k] = [] }

constants.each do |const|
  name = const[:name]
  case name
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
    puts "  #{const[:name]}"
  end
  puts "  ..." if categories[category].length > 5
end

# Generate the split files
puts "\n" + "=" * 50
puts "GENERATING SPLIT FILES"
puts "=" * 50

base_dir = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows'

# Create the main constants file that includes all others
main_file_content = <<~RUBY
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
# A container holding useful Windows API Constants.
# This file has been split into multiple category-specific files for maintainability.
#
class DefApiConstants_windows < ApiConstants

  #
  # Load constants from all category files
  #
  def self.add_constants(win_const_mgr)
RUBY

categories.keys.sort.each do |category|
  next if categories[category].empty?
  
  # Add require and method call to main file
  main_file_content += "    require_relative 'api_constants_#{category}'\n"
  main_file_content += "    DefApiConstants_#{category}.add_constants(win_const_mgr)\n"
  
  # Create category-specific file
  category_file_content = <<~RUBY
# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Windows API Constants - #{category.upcase} category
# Auto-generated from api_constants.rb split
#
class DefApiConstants_#{category}

  def self.add_constants(win_const_mgr)
RUBY

  categories[category].each do |const|
    category_file_content += "    win_const_mgr.add_const('#{const[:name]}',#{const[:value]})\n"
  end

  category_file_content += <<~RUBY
  end

end

end; end; end; end; end; end; end
RUBY

  # Write category file
  category_file_path = "#{base_dir}/api_constants_#{category}.rb"
  File.write(category_file_path, category_file_content)
  puts "Created: #{category_file_path} (#{categories[category].length} constants)"
end

main_file_content += <<~RUBY
  end

end

end; end; end; end; end; end; end
RUBY

# Write the new main file
new_main_file = "#{base_dir}/api_constants_new.rb"
File.write(new_main_file, main_file_content)
puts "Created: #{new_main_file}"

puts "\nSplit complete! #{categories.keys.length} category files created."
puts "Total constants distributed: #{constants.length}"
RUBY