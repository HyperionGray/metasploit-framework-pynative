#!/usr/bin/env python3
"""
Quick MSF Setup Test
"""

import sys
from pathlib import Path

# Test basic setup
MSF_ROOT = Path(__file__).parent
print(f"MSF Root: {MSF_ROOT}")

# Test msfrc exists
msfrc_path = MSF_ROOT / 'msfrc'
print(f"msfrc exists: {msfrc_path.exists()}")

# Test transpiler directory
transpiler_dir = MSF_ROOT / 'transpiler'
print(f"Transpiler dir exists: {transpiler_dir.exists()}")

if transpiler_dir.exists():
    subdirs = ['ruby2py', 'py2ruby', 'shared']
    for subdir in subdirs:
        subdir_path = transpiler_dir / subdir
        print(f"  {subdir}/ exists: {subdir_path.exists()}")

# Test config files
config_dir = MSF_ROOT / 'config'
print(f"Config dir exists: {config_dir.exists()}")

if config_dir.exists():
    config_files = ['boot.py', 'application.py']
    for config_file in config_files:
        config_path = config_dir / config_file
        print(f"  {config_file} exists: {config_path.exists()}")

# Test console scripts
console_scripts = ['msfconsole', 'msfd']
for script in console_scripts:
    script_path = MSF_ROOT / script
    print(f"{script} exists: {script_path.exists()}")

print("\n✅ Basic setup test completed!")