#!/usr/bin/env python3
"""
Manual implementation to split constants - processing line by line.
"""

import re
import os

def process_constants_file():
    """Process the constants file and split into categories."""
    
    input_file = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    output_dir = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants"
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Category files
    category_files = {}
    category_counts = {}
    
    # Initialize categories
    categories = ['errors', 'windows', 'registry', 'security', 'filesystem', 
                  'network', 'database', 'graphics', 'system', 'process', 'miscellaneous']
    
    for cat in categories:
        category_files[cat] = []
        category_counts[cat] = 0
    
    print("Processing constants file...")
    
    total_processed = 0
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # Skip non-constant lines
            if not 'win_const_mgr.add_const(' in line:
                continue
            
            # Extract constant using regex
            match = re.search(r"win_const_mgr\.add_const\('([^']+)',\s*(0x[0-9A-Fa-f]+)\)", line)
            if not match:
                print(f"Warning: Could not parse line {line_num}: {line}")
                continue
            
            const_name = match.group(1)
            const_value = match.group(2)
            
            # Categorize
            category = categorize_constant_simple(const_name)
            category_files[category].append((const_name, const_value))
            category_counts[category] += 1
            total_processed += 1
            
            if total_processed % 5000 == 0:
                print(f"  Processed {total_processed} constants...")
    
    print(f"Total processed: {total_processed}")
    print("\nCategory breakdown:")
    for cat in categories:
        print(f"  {cat}: {category_counts[cat]}")
    
    # Create category files
    create_all_category_files(category_files, output_dir)
    
    # Create main loader
    create_main_api_constants(categories, output_dir)
    
    return total_processed

def categorize_constant_simple(const_name):
    """Simple categorization based on prefixes."""
    
    # Error codes
    if (const_name.startswith('ERROR_') or 
        const_name.startswith('WSAE') or
        'ERROR' in const_name):
        return 'errors'
    
    # Window messages
    if (const_name.startswith('WM_') or 
        const_name.startswith('HWND_') or
        const_name.startswith('SW_')):
        return 'windows'
    
    # Registry
    if (const_name.startswith('HKEY_') or 
        const_name.startswith('REG_')):
        return 'registry'
    
    # Security
    if (const_name.startswith('CERT_') or 
        const_name.startswith('CRYPT_') or
        const_name.startswith('SEC_') or
        const_name.startswith('SECURITY_')):
        return 'security'
    
    # File system
    if (const_name.startswith('FILE_') or 
        const_name.startswith('DRIVE_') or
        const_name.startswith('GENERIC_')):
        return 'filesystem'
    
    # Network
    if (const_name.startswith('HTTP_') or 
        const_name.startswith('DNS_') or
        const_name.startswith('INTERNET_') or
        const_name.startswith('WINHTTP_')):
        return 'network'
    
    # Database
    if const_name.startswith('SQL_'):
        return 'database'
    
    # Graphics
    if (const_name.startswith('D3D') or 
        const_name.startswith('DD') or
        const_name.startswith('IMAGE_')):
        return 'graphics'
    
    # System
    if (const_name.startswith('PROCESSOR_') or 
        const_name.startswith('SYSTEM_')):
        return 'system'
    
    # Process
    if (const_name.startswith('JOB_') or 
        const_name.startswith('PROCESS_')):
        return 'process'
    
    # Default
    return 'miscellaneous'

def create_all_category_files(category_files, output_dir):
    """Create all category files."""
    
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
    
    for category, constants in category_files.items():
        if not constants:
            continue
            
        module_name, description = category_info[category]
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

def create_main_api_constants(categories, output_dir):
    """Create the main api_constants.rb file."""
    
    main_file = os.path.join(os.path.dirname(output_dir), 'api_constants.rb')
    
    category_modules = {
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
    
    print("Creating main api_constants.rb...")
    
    with open(main_file, 'w') as f:
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
        f.write("# The original monolithic file has been split into logical categories\n")
        f.write("# for better maintainability and organization.\n")
        f.write("#\n")
        f.write("class DefApiConstants_windows < ApiConstants\n")
        f.write("\n")
        f.write("  #\n")
        f.write("  # Load constants from all category modules.\n")
        f.write("  #\n")
        f.write("  def self.add_constants(win_const_mgr)\n")
        
        for category in categories:
            module_name = category_modules[category]
            f.write(f"    {module_name}.add_constants(win_const_mgr)\n")
        
        f.write("  end\n")
        f.write("\n")
        f.write("end\n")
        f.write("\n")
        f.write("end; end; end; end; end; end; end\n")

if __name__ == "__main__":
    print("Starting Windows API Constants Split...")
    total = process_constants_file()
    print(f"\nCompleted! Processed {total} constants.")