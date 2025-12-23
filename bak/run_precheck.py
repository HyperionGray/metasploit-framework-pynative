#!/usr/bin/env python3

import os
import sys
import subprocess

# Set working directory
os.chdir('/workspace')

print("🔍 PRE-MIGRATION CHECK - RUBY FILE INVENTORY")
print("=" * 50)

# Run the pre-migration check
try:
    result = subprocess.run([
        sys.executable, '/workspace/pre_migration_check.py'
    ], capture_output=False, text=True, cwd='/workspace')
    
    print(f"\nPre-check completed with return code: {result.returncode}")
    
except Exception as e:
    print(f"Error running pre-check: {e}")
    
print("\n✅ Pre-migration check complete!")