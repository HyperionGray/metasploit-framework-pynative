#!/usr/bin/env python3
"""
Complete implementation to split the Windows API constants file.
"""

import re
import os
from collections import defaultdict

def categorize_constant(const_name):
    """Categorize a constant based on its name patterns."""
    name_upper = const_name.upper()
    
    # Error codes - very specific patterns
    if (const_name.startswith('ERROR_') or 
        const_name.startswith('WSAE') or
        'ERROR' in const_name or
        const_name.endswith('_FAILED') or
        'INVALID' in const_name and ('HANDLE' in const_name or 'PARAMETER' in const_name)):
        return 'errors'
    
    # Window messages and UI - specific WM_ and window-related constants
    if (const_name.startswith('WM_') or 
        const_name.startswith('HWND_') or
        const_name.startswith('SW_') or
        const_name.startswith('SWP_') or
        const_name.startswith('WS_') or
        'WINDOW' in const_name or
        'DIALOG' in const_name or
        'MENU' in const_name):
        return 'windows'
    
    # Registry constants
    if (const_name.startswith('HKEY_') or 
        const_name.startswith('REG_') or
        const_name.startswith('KEY_') or
        'REGISTRY' in const_name):
        return 'registry'
    
    # Security and cryptography
    if (const_name.startswith('CERT_') or 
        const_name.startswith('CRYPT_') or
        const_name.startswith('SEC_') or
        const_name.startswith('AUTH_') or
        const_name.startswith('TRUST') or
        const_name.startswith('SECURITY_') or
        const_name.startswith('PRIVILEGE_') or
        const_name.startswith('TOKEN_') or
        const_name.startswith('ACL_') or
        const_name.startswith('SID_')):
        return 'security'
    
    # File system
    if (const_name.startswith('FILE_') or 
        const_name.startswith('DRIVE_') or
        const_name.startswith('VOLUME_') or
        const_name.startswith('DISK_') or
        const_name.startswith('DIRECTORY_') or
        const_name.startswith('GENERIC_READ') or
        const_name.startswith('GENERIC_WRITE')):
        return 'filesystem'
    
    # Network and HTTP
    if (const_name.startswith('HTTP_') or 
        const_name.startswith('DNS_') or
        const_name.startswith('WINHTTP_') or
        const_name.startswith('INTERNET_') or
        const_name.startswith('FTP_') or
        const_name.startswith('NET_') or
        const_name.startswith('SOCKET_') or
        const_name.startswith('AF_') or
        const_name.startswith('SOCK_')):
        return 'network'
    
    # Database and SQL
    if (const_name.startswith('SQL_') or 
        const_name.startswith('DB_') or
        const_name.startswith('ODBC_')):
        return 'database'
    
    # Graphics, DirectX, and imaging
    if (const_name.startswith('DD') or 
        const_name.startswith('D3D') or
        const_name.startswith('GDI_') or
        const_name.startswith('DIB_') or
        const_name.startswith('IMAGE_') or
        const_name.startswith('BITMAP_') or
        const_name.startswith('COLOR_')):
        return 'graphics'
    
    # System and hardware
    if (const_name.startswith('PROCESSOR_') or 
        const_name.startswith('DEVICE_') or
        const_name.startswith('SYSTEM_') or
        const_name.startswith('MACHINE_') or
        const_name.startswith('PLATFORM_')):
        return 'system'
    
    # Process and thread management
    if (const_name.startswith('JOB_') or 
        const_name.startswith('THREAD_') or
        const_name.startswith('PROCESS_') or
        const_name.startswith('WAIT_')):
        return 'process'
    
    # Default to miscellaneous
    return 'miscellaneous'

def extract_and_split_constants():
    """Extract constants and split them into categories."""
    
    input_file = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    output_dir = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants"
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract constants
    categories = defaultdict(list)
    total_constants = 0
    
    print("Extracting constants...")
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if 'win_const_mgr.add_const(' in line:
                # Extract using regex
                match = re.search(r"win_const_mgr\.add_const\('([^']+)',\s*(0x[0-9A-Fa-f]+)\)", line)
                if match:
                    const_name = match.group(1)
                    const_value = match.group(2)
                    category = categorize_constant(const_name)
                    categories[category].append((const_name, const_value))
                    total_constants += 1
                    
                    if total_constants % 5000 == 0:
                        print(f"  Processed {total_constants} constants...")
    
    print(f"Extracted {total_constants} constants into {len(categories)} categories")
    
    # Show category breakdown
    print("\nCategory breakdown:")
    for category in sorted(categories.keys()):
        print(f"  {category}: {len(categories[category])} constants")
    
    return categories, output_dir

def create_category_files(categories, output_dir):
    """Create Ruby files for each category."""
    
    category_info = {
        'errors': ('ApiConstantsErrors', 'Windows Error Codes and Status Values'),
        'windows': ('ApiConstantsWindows', 'Window Messages and UI Constants'),
        'registry': ('ApiConstantsRegistry', 'Registry Constants'),
        'security': ('ApiConstantsSecurity', 'Security and Cryptography Constants'),
        'filesystem': ('ApiConstantsFilesystem', 'File System Constants'),
        'network': ('ApiConstantsNetwork', 'Network and Internet Constants'),
        'database': ('ApiConstantsDatabase', 'Database and SQL Constants'),
        'graphics': ('ApiConstantsGraphics', 'Graphics and DirectX Constants'),
        'system': ('ApiConstantsSystem', 'System and Hardware Constants'),
        'process': ('ApiConstantsProcess', 'Process and Thread Constants'),
        'miscellaneous': ('ApiConstantsMiscellaneous', 'Miscellaneous Constants')
    }
    
    created_files = []
    
    for category, constants in categories.items():
        if not constants:
            continue
            
        module_name, description = category_info.get(category, (f'ApiConstants{category.title()}', f'{category.title()} Constants'))
        filename = f"{category}.rb"
        filepath = os.path.join(output_dir, filename)
        
        print(f"Creating {filename} with {len(constants)} constants...")
        
        with open(filepath, 'w') as f:
            f.write("# -*- coding: binary -*-\n")
            f.write(f"# {description}\n")
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
            
            # Sort constants alphabetically
            sorted_constants = sorted(constants, key=lambda x: x[0])
            
            for const_name, const_value in sorted_constants:
                f.write(f"    win_const_mgr.add_const('{const_name}',{const_value})\n")
            
            f.write("  end\n")
            f.write("end\n")
            f.write("\n")
            f.write("end; end; end; end; end; end; end\n")
        
        created_files.append((category, filename, len(constants)))
    
    return created_files

def create_main_loader(categories, output_dir):
    """Create the main api_constants.rb file."""
    
    main_file = os.path.join(os.path.dirname(output_dir), 'api_constants.rb')
    
    category_info = {
        'errors': 'ApiConstantsErrors',
        'windows': 'ApiConstantsWindows', 
        'registry': 'ApiConstantsRegistry',
        'security': 'ApiConstantsSecurity',
        'filesystem': 'ApiConstantsFilesystem',
        'network': 'ApiConstantsNetwork',
        'database': 'ApiConstantsDatabase',
        'graphics': 'ApiConstantsGraphics',
        'system': 'ApiConstantsSystem',
        'process': 'ApiConstantsProcess',
        'miscellaneous': 'ApiConstantsMiscellaneous'
    }
    
    print("Creating main api_constants.rb loader...")
    
    with open(main_file, 'w') as f:
        f.write("# -*- coding: binary -*-\n")
        f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'\n")
        f.write("\n")
        f.write("# Load all category modules\n")
        
        for category in sorted(categories.keys()):
            if categories[category]:  # Only include categories with constants
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
        f.write("# \n")
        f.write("# The original monolithic file has been split into logical categories\n")
        f.write("# for better maintainability and organization.\n")
        f.write("#\n")
        f.write("class DefApiConstants_windows < ApiConstants\n")
        f.write("\n")
        f.write("  #\n")
        f.write("  # Load constants from all category modules.\n")
        f.write("  #\n")
        f.write("  def self.add_constants(win_const_mgr)\n")
        
        for category in sorted(categories.keys()):
            if categories[category]:  # Only include categories with constants
                module_name = category_info.get(category, f'ApiConstants{category.title()}')
                f.write(f"    {module_name}.add_constants(win_const_mgr)\n")
        
        f.write("  end\n")
        f.write("\n")
        f.write("end\n")
        f.write("\n")
        f.write("end; end; end; end; end; end; end\n")

def main():
    """Main function to perform the split."""
    
    print("Windows API Constants Splitter")
    print("=" * 40)
    
    # Extract and categorize constants
    categories, output_dir = extract_and_split_constants()
    
    # Create category files
    print("\nCreating category files...")
    created_files = create_category_files(categories, output_dir)
    
    # Create main loader
    create_main_loader(categories, output_dir)
    
    # Summary
    print("\n" + "=" * 40)
    print("Split completed successfully!")
    print(f"Created {len(created_files)} category files:")
    
    total_constants = 0
    for category, filename, count in created_files:
        print(f"  {filename}: {count} constants")
        total_constants += count
    
    print(f"\nTotal constants: {total_constants}")
    print(f"Original file: 1 file with ~38,000 lines")
    print(f"New structure: {len(created_files)} files with manageable sizes")

if __name__ == "__main__":
    main()