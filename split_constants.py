#!/usr/bin/env python3

import re
import os
from collections import defaultdict

# Read the api_constants.rb file
file_path = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb'
with open(file_path, 'r') as f:
    content = f.read()

# Extract header and footer
lines = content.split('\n')
header_lines = []
footer_lines = []
constant_lines = []

in_constants = False
for line in lines:
    if 'def self.add_constants(win_const_mgr)' in line:
        in_constants = True
        header_lines.append(line)
        continue
    elif line.strip() == 'end' and in_constants:
        footer_lines.append(line)
        in_constants = False
        continue
    elif not in_constants and not footer_lines:
        header_lines.append(line)
    elif not in_constants and footer_lines:
        footer_lines.append(line)
    else:
        constant_lines.append(line)

# Extract all constants with their values
constants = []
for line in constant_lines:
    match = re.search(r"win_const_mgr\.add_const\('([^']+)',([^)]+)\)", line)
    if match:
        constants.append((match.group(1), match.group(2)))

print(f"Total constants found: {len(constants)}")

# Define categories based on prefixes and patterns
categories = {
    'errors': {
        'patterns': ['ERROR_', 'EXCEPTION_'],
        'description': 'Error codes and exception constants'
    },
    'windows_messages': {
        'patterns': ['WM_', 'BM_', 'CB_', 'EM_', 'LB_', 'STM_', 'DM_'],
        'description': 'Windows message constants'
    },
    'virtual_keys': {
        'patterns': ['VK_'],
        'description': 'Virtual key codes'
    },
    'language_locale': {
        'patterns': ['LANG_', 'SUBLANG_', 'LOCALE_', 'SORT_'],
        'description': 'Language and locale constants'
    },
    'network_dns': {
        'patterns': ['DNS_', 'NS_', 'WSAE'],
        'description': 'DNS and network service constants'
    },
    'sql_database': {
        'patterns': ['SQL_'],
        'description': 'SQL database constants'
    },
    'rpc_com': {
        'patterns': ['RPC_', 'CLSID_', 'IID_', 'DISPID_'],
        'description': 'RPC and COM constants'
    },
    'internet_http': {
        'patterns': ['INTERNET_', 'WINHTTP_', 'HTTP_', 'URL'],
        'description': 'Internet and HTTP constants'
    },
    'security_crypto': {
        'patterns': ['CERT_', 'CRYPT', 'SECURITY_', 'SCARD_'],
        'description': 'Security and cryptography constants'
    },
    'services_system': {
        'patterns': ['SERVICE_', 'SC_', 'SERVICES_'],
        'description': 'System services constants'
    },
    'file_io': {
        'patterns': ['FILE_', 'GENERIC_', 'STANDARD_', 'CREATE_'],
        'description': 'File I/O and access constants'
    },
    'registry': {
        'patterns': ['REG', 'HKEY_', 'KEY_'],
        'description': 'Registry constants'
    },
    'process_thread': {
        'patterns': ['PROCESS_', 'THREAD_', 'TOKEN_', 'JOB_'],
        'description': 'Process and thread constants'
    },
    'image_debug': {
        'patterns': ['IMAGE_', 'DEBUG_'],
        'description': 'Image and debugging constants'
    },
    'ui_controls': {
        'patterns': ['COLOR_', 'BRUSH_', 'PEN_', 'FONT_', 'ICON_', 'CURSOR_', 'MENU_', 'DIALOG_'],
        'description': 'UI and control constants'
    },
    'device_hardware': {
        'patterns': ['DEVICE_', 'DRIVER_', 'PRINTER_', 'TAPE_'],
        'description': 'Device and hardware constants'
    },
    'multimedia': {
        'patterns': ['MCI_', 'WAVE_', 'MIDI_', 'SOUND_'],
        'description': 'Multimedia constants'
    },
    'networking': {
        'patterns': ['SOCKET_', 'TCP_', 'UDP_', 'IP_', 'FTP_', 'SMTP_'],
        'description': 'Network protocol constants'
    }
}

# Categorize constants
categorized_constants = defaultdict(list)
uncategorized_constants = []

for const_name, const_value in constants:
    categorized = False
    for category, info in categories.items():
        for pattern in info['patterns']:
            if const_name.startswith(pattern):
                categorized_constants[category].append((const_name, const_value))
                categorized = True
                break
        if categorized:
            break
    
    if not categorized:
        uncategorized_constants.append((const_name, const_value))

# Create a miscellaneous category for uncategorized constants
if uncategorized_constants:
    categorized_constants['miscellaneous'] = uncategorized_constants
    categories['miscellaneous'] = {
        'patterns': [],
        'description': 'Miscellaneous constants'
    }

# Print statistics
print("\nCategory statistics:")
total_categorized = 0
for category, consts in categorized_constants.items():
    print(f"{category}: {len(consts)} constants")
    total_categorized += len(consts)

print(f"\nTotal categorized: {total_categorized}")

# Create directory structure
base_dir = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants'
os.makedirs(base_dir, exist_ok=True)

# Generate category files
for category, consts in categorized_constants.items():
    if not consts:
        continue
        
    filename = f"{base_dir}/{category}.rb"
    
    with open(filename, 'w') as f:
        # Write header
        f.write("# -*- coding: binary -*-\n")
        f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'\n\n")
        f.write("module Rex\n")
        f.write("module Post\n")
        f.write("module Meterpreter\n")
        f.write("module Extensions\n")
        f.write("module Stdapi\n")
        f.write("module Railgun\n")
        f.write("module Def\n\n")
        f.write("#\n")
        f.write(f"# {categories[category]['description']}\n")
        f.write("#\n")
        f.write(f"class DefApiConstants{category.title().replace('_', '')} < ApiConstants\n\n")
        f.write("  #\n")
        f.write(f"  # Add {category.replace('_', ' ')} constants\n")
        f.write("  #\n")
        f.write("  def self.add_constants(win_const_mgr)\n")
        
        # Write constants
        for const_name, const_value in consts:
            f.write(f"    win_const_mgr.add_const('{const_name}',{const_value})\n")
        
        # Write footer
        f.write("  end\n\n")
        f.write("end\n\n")
        f.write("end; end; end; end; end; end; end\n")

print(f"\nCreated {len(categorized_constants)} category files in {base_dir}")

# Create an index file that loads all categories
index_filename = f"{base_dir}/index.rb"
with open(index_filename, 'w') as f:
    f.write("# -*- coding: binary -*-\n\n")
    f.write("# Auto-generated index file for Windows API constants\n")
    f.write("# This file loads all constant categories\n\n")
    
    for category in sorted(categorized_constants.keys()):
        f.write(f"require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/{category}'\n")
    
    f.write("\nmodule Rex\n")
    f.write("module Post\n")
    f.write("module Meterpreter\n")
    f.write("module Extensions\n")
    f.write("module Stdapi\n")
    f.write("module Railgun\n")
    f.write("module Def\n\n")
    f.write("#\n")
    f.write("# Loads all Windows API constants from categorized files\n")
    f.write("#\n")
    f.write("class DefApiConstantsIndex\n")
    f.write("  def self.add_constants(win_const_mgr)\n")
    
    for category in sorted(categorized_constants.keys()):
        class_name = f"DefApiConstants{category.title().replace('_', '')}"
        f.write(f"    {class_name}.add_constants(win_const_mgr)\n")
    
    f.write("  end\n")
    f.write("end\n\n")
    f.write("end; end; end; end; end; end; end\n")

print(f"Created index file: {index_filename}")

# Create a new main api_constants.rb that uses the index
new_main_file = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants_new.rb'
with open(new_main_file, 'w') as f:
    f.write("# -*- coding: binary -*-\n")
    f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'\n")
    f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/index'\n\n")
    f.write("module Rex\n")
    f.write("module Post\n")
    f.write("module Meterpreter\n")
    f.write("module Extensions\n")
    f.write("module Stdapi\n")
    f.write("module Railgun\n")
    f.write("module Def\n\n")
    f.write("#\n")
    f.write("# A container holding useful Windows API Constants.\n")
    f.write("# This version loads constants from categorized files for better maintainability.\n")
    f.write("#\n")
    f.write("class DefApiConstants_windows < ApiConstants\n\n")
    f.write("  #\n")
    f.write("  # Load constants from all categorized files.\n")
    f.write("  #\n")
    f.write("  def self.add_constants(win_const_mgr)\n")
    f.write("    DefApiConstantsIndex.add_constants(win_const_mgr)\n")
    f.write("  end\n\n")
    f.write("end\n\n")
    f.write("end; end; end; end; end; end; end\n")

print(f"Created new main file: {new_main_file}")
print("\nSplitting complete! The original 38,209-line file has been split into:")
print(f"- {len(categorized_constants)} category files")
print("- 1 index file")
print("- 1 new main file")
print("\nTo use the new structure, replace the original api_constants.rb with api_constants_new.rb")