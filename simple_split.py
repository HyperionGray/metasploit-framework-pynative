#!/usr/bin/env python3

import re
import os

# Read the original file
with open('/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb', 'r') as f:
    content = f.read()

# Extract all constants
constants = re.findall(r"win_const_mgr\.add_const\('([^']+)',([^)]+)\)", content)
print(f"Found {len(constants)} constants")

# Simple categorization by prefix
categories = {}
for const_name, const_value in constants:
    if const_name.startswith('ERROR_'):
        category = 'errors'
    elif const_name.startswith('WM_'):
        category = 'windows_messages'
    elif const_name.startswith('VK_'):
        category = 'virtual_keys'
    elif const_name.startswith(('LANG_', 'SUBLANG_')):
        category = 'language'
    elif const_name.startswith('DNS_'):
        category = 'dns'
    elif const_name.startswith('SQL_'):
        category = 'sql'
    elif const_name.startswith('RPC_'):
        category = 'rpc'
    elif const_name.startswith(('INTERNET_', 'WINHTTP_', 'HTTP_')):
        category = 'internet'
    elif const_name.startswith(('CERT_', 'CRYPT')):
        category = 'crypto'
    elif const_name.startswith('SERVICE_'):
        category = 'services'
    elif const_name.startswith(('FILE_', 'GENERIC_')):
        category = 'file_io'
    elif const_name.startswith(('REG', 'HKEY_', 'KEY_')):
        category = 'registry'
    elif const_name.startswith(('PROCESS_', 'THREAD_', 'TOKEN_')):
        category = 'process'
    elif const_name.startswith(('IMAGE_', 'DEBUG_')):
        category = 'debug'
    else:
        category = 'misc'
    
    if category not in categories:
        categories[category] = []
    categories[category].append((const_name, const_value))

# Create category files
base_dir = '/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants'

for category, consts in categories.items():
    filename = f"{base_dir}/{category}.rb"
    
    with open(filename, 'w') as f:
        f.write("# -*- coding: binary -*-\n")
        f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'\n\n")
        f.write("module Rex\nmodule Post\nmodule Meterpreter\nmodule Extensions\nmodule Stdapi\nmodule Railgun\nmodule Def\n\n")
        f.write(f"class DefApiConstants{category.title()} < ApiConstants\n")
        f.write("  def self.add_constants(win_const_mgr)\n")
        
        for const_name, const_value in consts:
            f.write(f"    win_const_mgr.add_const('{const_name}',{const_value})\n")
        
        f.write("  end\nend\n\n")
        f.write("end; end; end; end; end; end; end\n")

print(f"Created {len(categories)} category files")

# Create index file
with open(f"{base_dir}/index.rb", 'w') as f:
    f.write("# -*- coding: binary -*-\n\n")
    for category in sorted(categories.keys()):
        f.write(f"require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/{category}'\n")
    
    f.write("\nmodule Rex\nmodule Post\nmodule Meterpreter\nmodule Extensions\nmodule Stdapi\nmodule Railgun\nmodule Def\n\n")
    f.write("class DefApiConstantsIndex\n")
    f.write("  def self.add_constants(win_const_mgr)\n")
    
    for category in sorted(categories.keys()):
        f.write(f"    DefApiConstants{category.title()}.add_constants(win_const_mgr)\n")
    
    f.write("  end\nend\n\n")
    f.write("end; end; end; end; end; end; end\n")

# Create new main file
with open('/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants_new.rb', 'w') as f:
    f.write("# -*- coding: binary -*-\n")
    f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/const_manager'\n")
    f.write("require 'rex/post/meterpreter/extensions/stdapi/railgun/def/windows/constants/index'\n\n")
    f.write("module Rex\nmodule Post\nmodule Meterpreter\nmodule Extensions\nmodule Stdapi\nmodule Railgun\nmodule Def\n\n")
    f.write("class DefApiConstants_windows < ApiConstants\n")
    f.write("  def self.add_constants(win_const_mgr)\n")
    f.write("    DefApiConstantsIndex.add_constants(win_const_mgr)\n")
    f.write("  end\nend\n\n")
    f.write("end; end; end; end; end; end; end\n")

print("Split complete!")