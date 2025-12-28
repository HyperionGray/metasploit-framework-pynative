#!/usr/bin/env ruby

# Production script to split the massive Windows API constants file
require 'fileutils'

def categorize_constant(const_name)
  case const_name
  when /^(HWND_|WM_|WS_|SW_|SWP_|SHOW_|WINDOW_|WA_|WDA_|WPF_|WMSZ_|HTMAXBUTTON|HTMINBUTTON|HTCLOSE|HTCAPTION|HTCLIENT)/
    'window_management'
  when /^(ERROR_|NERR_|DNS_ERROR_|RPC_S_|SEC_E_|RPC_X_|WSAE|CRYPT_E_)/
    'error_codes'
  when /^(REG|HKEY_|KEY_|CM_|CONFIGFLAG_|CONFIGRET_)/
    'registry_config'
  when /^(FILE_|GENERIC_|CREATE_|OPEN_|SHARE_|SECURITY_|ACCESS_|STANDARD_RIGHTS_|PIPE_)/
    'file_security'
  when /^(PROCESS_|THREAD_|TOKEN_|SE_|PRIVILEGE_)/
    'process_security'
  when /^(DNS_|NS_|AF_|PF_|SOCK_|IPPROTO_|IF_TYPE_|IN_CLASS)/
    'network_dns'
  when /^(CERT_|CRYPT_|ALG_|CALG_|PROV_|CMSG_|CRYPTNET_|CRYPTDLG_)/
    'crypto_certificates'
  when /^(MCI_|WAVE_|MIXER_|MM_|MIDI_|ICERR_|ICDRAW_)/
    'multimedia'
  when /^(SERVICE_|SC_|SERVICES_|SV_)/
    'services'
  when /^(EVENT_|EVENTLOG_|TRACE_)/
    'events_logging'
  when /^(PRINTER_|DRIVER_|DM_|DEVMODE_|PRINT_|JOB_NOTIFY_)/
    'printing'
  when /^(LANG_|SUBLANG_|LOCALE_|CP_|SORT_)/
    'locale_language'
  when /^(IMAGE_|PE_|SECTION_|RELOC_)/
    'pe_image'
  when /^(DEVICE_|IOCTL_|CTL_CODE|DN_|DIF_|DICS_|SPDRP_)/
    'device_io'
  when /^(TRUSTEE_|AUDIT_|ACE_|SDDL_)/
    'access_control'
  when /^(INTERNET_|WINHTTP_|HTTP_)/
    'internet_http'
  when /^(VK_|XINPUT_|RIM_)/
    'input_devices'
  when /^(DISPID_|IDD_|IDC_|IDI_|CB_|LB_|LVS_)/
    'ui_resources'
  when /^(SQL_|KAGPROPVAL_)/
    'database'
  when /^(TAPE_|FD_|EXCEPTION_|DEBUG_)/
    'system_hardware'
  else
    'miscellaneous'
  end
end

def backup_original_file(input_file)
  backup_file = input_file + '.backup'
  unless File.exist?(backup_file)
    FileUtils.cp(input_file, backup_file)
    puts "Created backup: #{backup_file}"
  else
    puts "Backup already exists: #{backup_file}"
  end
end

def split_constants_file_production(input_file, output_dir)
  # Create backup first
  backup_original_file(input_file)
  
  # Create output directory
  FileUtils.mkdir_p(output_dir)
  
  # Hash to store constants by category
  categories = Hash.new { |h, k| h[k] = [] }
  
  puts "Reading constants from #{input_file}..."
  
  # Read and categorize constants
  File.readlines(input_file).each_with_index do |line, index|
    if line.match(/^\s*win_const_mgr\.add_const\('([^']+)',(.+)\)/)
      const_name = $1
      const_value = $2
      category = categorize_constant(const_name)
      categories[category] << "    win_const_mgr.add_const('#{const_name}',#{const_value})"
      
      if (index + 1) % 5000 == 0
        puts "Processed #{index + 1} lines..."
      end
    end
  end
  
  puts "Creating category files..."
  
  # Create category files
  categories.each do |category, constants|
    filename = File.join(output_dir, "#{category}_constants.rb")
    File.open(filename, 'w') do |f|
      f.puts "# -*- coding: binary -*-"
      f.puts ""
      f.puts "module Rex"
      f.puts "module Post"
      f.puts "module Meterpreter"
      f.puts "module Extensions"
      f.puts "module Stdapi"
      f.puts "module Railgun"
      f.puts "module Def"
      f.puts ""
      f.puts "# Windows API Constants - #{category.gsub('_', ' ').split.map(&:capitalize).join(' ')}"
      f.puts "class #{category.split('_').map(&:capitalize).join}Constants"
      f.puts "  def self.add_constants(win_const_mgr)"
      constants.each { |const| f.puts const }
      f.puts "  end"
      f.puts "end"
      f.puts ""
      f.puts "end; end; end; end; end; end; end"
    end
    puts "Created #{filename} with #{constants.length} constants"
  end
  
  # Create the new main file
  new_main_file = input_file.gsub('.rb', '_split.rb')
  File.open(new_main_file, 'w') do |f|
    f.puts "# -*- coding: binary -*-"
    f.puts "require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'"
    f.puts ""
    
    # Require all category files
    categories.keys.sort.each do |category|
      f.puts "require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/#{category}_constants'"
    end
    f.puts ""
    
    f.puts "module Rex"
    f.puts "module Post"
    f.puts "module Meterpreter"
    f.puts "module Extensions"
    f.puts "module Stdapi"
    f.puts "module Railgun"
    f.puts "module Def"
    f.puts ""
    f.puts "#"
    f.puts "# A container holding useful Windows API Constants."
    f.puts "# This file loads constants from categorized files for better maintainability."
    f.puts "# Original monolithic file had 38,000+ lines and has been split into #{categories.length} category files."
    f.puts "#"
    f.puts "class DefApiConstants_windows < ApiConstants"
    f.puts ""
    f.puts "  #"
    f.puts "  # Load constants from all category files"
    f.puts "  #"
    f.puts "  def self.add_constants(win_const_mgr)"
    
    # Add calls to load each category
    categories.keys.sort.each do |category|
      class_name = category.split('_').map(&:capitalize).join + 'Constants'
      f.puts "    #{class_name}.add_constants(win_const_mgr)"
    end
    
    f.puts "  end"
    f.puts ""
    f.puts "end"
    f.puts ""
    f.puts "end; end; end; end; end; end; end"
  end
  
  puts "\nSplit complete!"
  puts "Created new main file: #{new_main_file}"
  puts "Original file backed up as: #{input_file}.backup"
  puts "Total categories: #{categories.length}"
  puts "Total constants: #{categories.values.map(&:length).sum}"
  puts "\nCategory breakdown:"
  categories.sort_by { |k, v| -v.length }.each do |category, constants|
    puts "  #{category}: #{constants.length} constants"
  end
  
  puts "\nTo use the new split version:"
  puts "1. Test the new file: #{new_main_file}"
  puts "2. If tests pass, replace the original file"
  puts "3. Update any require statements that reference the original file"
end

if __FILE__ == $0
  input_file = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
  output_dir = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants'
  
  split_constants_file_production(input_file, output_dir)
end