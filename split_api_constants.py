#!/usr/bin/env python3

import re
import os
from collections import defaultdict

def categorize_constant(name):
    """Categorize a constant based on its name pattern"""
    
    # Error codes
    if re.match(r'^ERROR_', name):
        return 'errors'
    
    # Windows UI and messaging
    if re.match(r'^(WM_|HWND_|WS_|SW_|SWP_|VK_|IDC_|IDI_|MB_|IDOK|IDCANCEL|IDYES|IDNO|BM_|CB_|LB_|EM_|SB_|TB_|TBM_|UDM_|LVM_|TVM_|HDM_|TCM_|PGM_|MCM_|DTM_|IPM_|CCM_)', name):
        return 'ui_windows'
    
    # Registry
    if re.match(r'^(REG|HKEY_|KEY_)', name):
        return 'registry'
    
    # File I/O
    if re.match(r'^(FILE_|GENERIC_|CREATE_|OPEN_|SHARE_|MOVEFILE_|REPLACEFILE_)', name):
        return 'file_io'
    
    # Process and security
    if re.match(r'^(PROCESS_|THREAD_|TOKEN_|SE_|SECURITY_|DOMAIN_|POLICY_)', name):
        return 'process_security'
    
    # Services
    if re.match(r'^(SERVICE_|SC_)', name):
        return 'services'
    
    # Network
    if re.match(r'^(DNS_|SOCKET_|AF_|SOCK_|IPPROTO_|TCP_|UDP_|IP_|WSAE|WSA_|FD_|INTERNET_|WINHTTP_|HTTP_)', name):
        return 'network'
    
    # Cryptography
    if re.match(r'^(CERT_|CRYPT|ALG_|CALG_|PROV_|PKCS_)', name):
        return 'cryptography'
    
    # Locale and language
    if re.match(r'^(LANG_|SUBLANG_|SORT_|LOCALE_)', name):
        return 'locale'
    
    # Database
    if re.match(r'^(SQL_|ODBC_)', name):
        return 'database'
    
    # Printing
    if re.match(r'^(PRINTER_|PRINT_|DM_)', name):
        return 'printing'
    
    # Multimedia
    if re.match(r'^(MCI_|WAVE_|MIDI_|MM_)', name):
        return 'multimedia'
    
    # PE format
    if re.match(r'^(IMAGE_|PE_|SECTION_)', name):
        return 'pe_format'
    
    # Device I/O
    if re.match(r'^(TAPE_|IOCTL_)', name):
        return 'device_io'
    
    # RPC
    if re.match(r'^(RPC_|NDR_)', name):
        return 'rpc'
    
    # SNMP
    if re.match(r'^SNMP_', name):
        return 'snmp'
    
    # COM/OLE
    if re.match(r'^(DISPID_|IID_|CLSID_|OLEUI_)', name):
        return 'com_ole'
    
    # DirectX/Graphics
    if re.match(r'^(D3D|DXVA_|EMR_)', name):
        return 'graphics'
    
    # Everything else
    return 'misc'

def main():
    # Read the constants file
    constants_file = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
    with open(constants_file, 'r') as f:
        content = f.read()

    # Extract all constant names and values
    constants = []
    pattern = r"win_const_mgr\.add_const\('([^']+)',([^)]+)\)"
    matches = re.findall(pattern, content)

    for match in matches:
        constants.append({'name': match[0], 'value': match[1]})

    print(f"Total constants found: {len(constants)}")

    # Categorize constants
    categories = defaultdict(list)
    for const in constants:
        category = categorize_constant(const['name'])
        categories[category].append(const)

    # Print categorization results
    print("\nCategorization Results:")
    print("=" * 50)

    for category in sorted(categories.keys()):
        print(f"{category.upper()}: {len(categories[category])} constants")

    print("\nTop 10 categories by size:")
    sorted_categories = sorted(categories.items(), key=lambda x: len(x[1]), reverse=True)
    for category, consts in sorted_categories[:10]:
        print(f"  {category}: {len(consts)}")

    # Show some examples from each category
    print("\nExamples from each category:")
    for category in sorted(categories.keys()):
        if len(categories[category]) > 0:
            print(f"\n{category.upper()} ({len(categories[category])} total):")
            for const in categories[category][:5]:
                print(f"  {const['name']}")
            if len(categories[category]) > 5:
                print("  ...")

    print("\n" + "=" * 50)
    print("GENERATING SPLIT FILES")
    print("=" * 50)

    base_dir = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows'

    # Create category-specific files
    for category in sorted(categories.keys()):
        if not categories[category]:
            continue
        
        # Create category-specific file
        category_file_content = f"""# -*- coding: binary -*-

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

#
# Windows API Constants - {category.upper()} category
# Auto-generated from api_constants.rb split
#
class DefApiConstants_{category}

  def self.add_constants(win_const_mgr)
"""

        for const in categories[category]:
            category_file_content += f"    win_const_mgr.add_const('{const['name']}',{const['value']})\n"

        category_file_content += """  end

end

end; end; end; end; end; end; end
"""

        # Write category file
        category_file_path = f"{base_dir}/api_constants_{category}.rb"
        with open(category_file_path, 'w') as f:
            f.write(category_file_content)
        print(f"Created: {category_file_path} ({len(categories[category])} constants)")

    # Create the main constants file that includes all others
    main_file_content = """# -*- coding: binary -*-
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
"""

    for category in sorted(categories.keys()):
        if not categories[category]:
            continue
        
        # Add require and method call to main file
        main_file_content += f"    require_relative 'api_constants_{category}'\n"
        main_file_content += f"    DefApiConstants_{category}.add_constants(win_const_mgr)\n"

    main_file_content += """  end

end

end; end; end; end; end; end; end
"""

    # Write the new main file
    new_main_file = f"{base_dir}/api_constants_new.rb"
    with open(new_main_file, 'w') as f:
        f.write(main_file_content)
    print(f"Created: {new_main_file}")

    print(f"\nSplit complete! {len(categories.keys())} category files created.")
    print(f"Total constants distributed: {len(constants)}")

if __name__ == "__main__":
    main()