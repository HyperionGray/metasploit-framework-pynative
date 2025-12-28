#!/usr/bin/env ruby

# Script to extract and analyze a sample of constants
def extract_sample_constants(input_file, sample_size = 1000)
  constants = []
  
  File.readlines(input_file).each_with_index do |line, index|
    if line.match(/win_const_mgr\.add_const\('([^']+)',(.+)\)/)
      const_name = $1
      const_value = $2
      constants << { name: const_name, value: const_value, line: index + 1 }
      break if constants.length >= sample_size
    end
  end
  
  constants
end

def categorize_constant(const_name)
  case const_name
  when /^(HWND_|WM_|WS_|SW_|SWP_|SHOW_|WINDOW_|WA_|WDA_|WPF_|WMSZ_)/
    'window_management'
  when /^(ERROR_|NERR_|DNS_ERROR_|RPC_S_|SEC_E_|RPC_X_|WSAE|CRYPT_E_)/
    'error_codes'
  when /^(REG|HKEY_|KEY_|CM_|CONFIGFLAG_|CONFIGRET_)/
    'registry_config'
  when /^(FILE_|GENERIC_|CREATE_|OPEN_|SHARE_|SECURITY_|ACCESS_|STANDARD_RIGHTS_)/
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
  when /^(PRINTER_|DRIVER_|DM_|DEVMODE_|PRINT_)/
    'printing'
  when /^(LANG_|SUBLANG_|LOCALE_|CP_|SORT_)/
    'locale_language'
  when /^(IMAGE_|PE_|SECTION_|RELOC_)/
    'pe_image'
  when /^(DEVICE_|IOCTL_|CTL_CODE|DN_|DIF_|DICS_)/
    'device_io'
  when /^(TRUSTEE_|AUDIT_|ACE_|SDDL_)/
    'access_control'
  when /^(INTERNET_|WINHTTP_|HTTP_)/
    'internet_http'
  when /^(VK_|XINPUT_|RIM_)/
    'input_devices'
  when /^(DISPID_|IDD_|IDC_|IDI_)/
    'ui_resources'
  when /^(SQL_|KAGPROPVAL_)/
    'database'
  when /^(TAPE_|FD_|EXCEPTION_)/
    'system_hardware'
  else
    'miscellaneous'
  end
end

if __FILE__ == $0
  input_file = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
  
  puts "Extracting sample constants..."
  constants = extract_sample_constants(input_file, 1000)
  
  puts "Analyzing #{constants.length} constants..."
  
  categories = Hash.new(0)
  constants.each do |const|
    category = categorize_constant(const[:name])
    categories[category] += 1
  end
  
  puts "\nCategory distribution (first 1000 constants):"
  categories.sort_by { |k, v| -v }.each do |category, count|
    puts "#{category}: #{count} constants"
  end
  
  puts "\nSample constants by category:"
  categories.keys.each do |category|
    sample_consts = constants.select { |c| categorize_constant(c[:name]) == category }.first(3)
    puts "\n#{category.upcase}:"
    sample_consts.each { |c| puts "  #{c[:name]}" }
  end
end