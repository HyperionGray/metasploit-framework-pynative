#!/usr/bin/env python3

import os
import sys
import subprocess

# Change to workspace directory  
os.chdir('/workspace')

print("Running Ruby Module Discovery...")
print("=" * 40)

# Run discovery script directly
discovery_script = '/workspace/tools/dev/discover_post_2020_exploits.py'

try:
    result = subprocess.run([sys.executable, discovery_script], 
                          capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    
    print(f"\nReturn code: {result.returncode}")
    
except Exception as e:
    print(f"Error running discovery: {e}")