#!/usr/bin/env python3
"""
Split the massive Windows API constants file into logical categories.
"""

import re
import os
from collections import defaultdict

def categorize_constant(const_name):
    """Categorize a constant based on its name."""
    name_upper = const_name.upper()
    
    # Error codes
    if any(x in name_upper for x in ['ERROR_', 'WSAE', '_ERR', 'FAILED', 'INVALID']):
        return 'errors'
    
    # Window messages and UI
    if any(x in name_upper for x in ['WM_', 'WS_', 'SW_', 'SWP_', 'HWND_', 'MSG_', 'WINDOW', 'DIALOG', 'MENU', 'BUTTON', 'SCROLL']):
        return 'windows'
    
    # Registry
    if any(x in name_upper for x in ['HKEY_', 'REG_', 'KEY_', 'REGISTRY']):
        return 'registry'
    
    # Security and cryptography
    if any(x in name_upper for x in ['CERT_', 'CRYPT_', 'SEC_', 'AUTH_', 'TRUST_', 'SECURITY_', 'PRIVILEGE_', 'TOKEN_', 'ACL_', 'SID_']):
        return 'security'
    
    # File system
    if any(x in name_upper for x in ['FILE_', 'DRIVE_', 'VOLUME_', 'DISK_', 'DIRECTORY_', 'FOLDER_', 'PATH_', 'GENERIC_READ', 'GENERIC_WRITE']):
        return 'filesystem'
    
    # Network
    if any(x in name_upper for x in ['HTTP_', 'DNS_', 'TCP_', 'UDP_', 'IP_', 'SOCKET_', 'NET_', 'INTERNET_', 'WINHTTP_', 'FTP_', 'SMTP_']):
        return 'network'
    
    # Database
    if any(x in name_upper for x in ['SQL_', 'DB_', 'DATABASE_', 'ODBC_']):
        return 'database'
    
    # Graphics and DirectX
    if any(x in name_upper for x in ['DD', 'D3D', 'GDI_', 'DIB_', 'BMP_', 'IMAGE_', 'BITMAP_', 'COLOR_', 'BRUSH_', 'PEN_', 'FONT_']):
        return 'graphics'
    
    # System and hardware
    if any(x in name_upper for x in ['PROCESSOR_', 'DEVICE_', 'HARDWARE_', 'SYSTEM_', 'MACHINE_', 'PLATFORM_', 'ARCH_']):
        return 'system'
    
    # Process and thread
    if any(x in name_upper for x in ['JOB_', 'THREAD_', 'PROCESS_', 'HANDLE_', 'WAIT_', 'SYNCHRONIZE']):
        return 'process'
    
    # Default to miscellaneous
    return 'miscellaneous'

def extract_constants_from_file(filepath):
    """Extract all constants from the original file."""
    constants = []
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            # Look for add_const lines
            if 'win_const_mgr.add_const(' in line:
                # Extract constant name and value using regex
                match = re.search(r"win_const_mgr\.add_const\('([^']+)',\s*(0x[0-9A-Fa-f]+)\)", line)
                if match:
                    const_name = match.group(1)
                    const_value = match.group(2)
                    category = categorize_constant(const_name)
                    constants.append((const_name, const_value, category))
                else:
                    print(f"Warning: Could not parse line {line_num}: {line}")
    
    return constants

def create_category_file(category, constants, output_dir):
    """Create a Ruby file for a specific category."""
    
    category_descriptions = {
        'errors': 'Windows Error Codes and Status Values',
        'windows': 'Window Messages and UI Constants',
        'registry': 'Registry Constants',
        'security': 'Security and Cryptography Constants',
        'filesystem': 'File System Constants',
        'network': 'Network and Internet Constants',
        'database': 'Database and SQL Constants',
        'graphics': 'Graphics and DirectX Constants',
        'system': 'System and Hardware Constants',
        'process': 'Process and Thread Constants',
        'miscellaneous': 'Miscellaneous Constants'
    }
    
    module_name = f"ApiConstants{category.title()}"
    filename = f"{category}.rb"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        f.write("# -*- coding: binary -*-\n")
        f.write(f"# {category_descriptions.get(category, 'Constants')}\n")
        f.write("# This file was automatically generated from the original api_constants.rb\n")
        f.write("\n")
        f.write("module Rex\n")
        f.write("module Post\n")
        f.write("module Meterpreter\n")
        f.write("module Extensions\n")
        f.write("module Stdapi\n")
        f.write("module Railgun\n")
        f.write("module Def\n")
        f.write("\n")
        f.write(f"module {module_name}\n")
        f.write("  def self.add_constants(win_const_mgr)\n")
        
        # Sort constants alphabetically for better organization
        sorted_constants = sorted(constants, key=lambda x: x[0])
        
        for const_name, const_value, _ in sorted_constants:
            f.write(f"    win_const_mgr.add_const('{const_name}',{const_value})\n")
        
        f.write("  end\n")
        f.write("end\n")
        f.write("\n")
        f.write("end; end; end; end; end; end; end\n")
    
    print(f"Created {filename} with {len(constants)} constants")

def create_main_loader(output_dir):
    """Create the main api_constants.rb file that loads all categories."""
    
    categories = ['errors', 'windows', 'registry', 'security', 'filesystem', 
                  'network', 'database', 'graphics', 'system', 'process', 'miscellaneous']
    
    filepath = os.path.join(os.path.dirname(output_dir), 'api_constants.rb')
    
    with open(filepath, 'w') as f:
        f.write("# -*- coding: binary -*-\n")
        f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'\n")
        f.write("\n")
        f.write("# Load all category modules\n")
        for category in categories:
            f.write(f"require_relative 'constants/{category}'\n")
        f.write("\n")
        f.write("module Rex\n")
        f.write("module Post\n")
        f.write("module Meterpreter\n")
        f.write("module Extensions\n")
        f.write("module Stdapi\n")
        f.write("module Railgun\n")
        f.write("module Def\n")
        f.write("\n")
        f.write("#\n")
        f.write("# A container holding useful Windows API Constants.\n")
        f.write("# This class loads constants from multiple category modules.\n")
        f.write("#\n")
        f.write("class DefApiConstants_windows < ApiConstants\n")
        f.write("\n")
        f.write("  #\n")
        f.write("  # Load constants from all category modules.\n")
        f.write("  #\n")
        f.write("  def self.add_constants(win_const_mgr)\n")
        
        for category in categories:
            module_name = f"ApiConstants{category.title()}"
            f.write(f"    {module_name}.add_constants(win_const_mgr)\n")
        
        f.write("  end\n")
        f.write("\n")
        f.write("end\n")
        f.write("\n")
        f.write("end; end; end; end; end; end; end\n")
    
    print(f"Created main api_constants.rb loader")

def main():
    """Main function to split the constants file."""
    
    input_file = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    output_dir = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants"
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    print("Extracting constants from original file...")
    constants = extract_constants_from_file(input_file)
    print(f"Found {len(constants)} constants")
    
    # Group constants by category
    categories = defaultdict(list)
    for const_name, const_value, category in constants:
        categories[category].append((const_name, const_value, category))
    
    print("\nConstants by category:")
    for category, consts in categories.items():
        print(f"  {category}: {len(consts)} constants")
    
    # Create category files
    print("\nCreating category files...")
    for category, consts in categories.items():
        create_category_file(category, consts, output_dir)
    
    # Create main loader
    print("\nCreating main loader...")
    create_main_loader(output_dir)
    
    print("\nSplit complete!")
    print(f"Original file: {len(constants)} constants in 1 file")
    print(f"New structure: {len(constants)} constants in {len(categories)} category files")

if __name__ == "__main__":
    main()