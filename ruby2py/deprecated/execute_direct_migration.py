#!/usr/bin/env python3

import subprocess
import sys
import os

os.chdir('/workspace')

print("Executing Ruby to Python Migration...")
print("=" * 40)

try:
    # Run the direct migration script
    result = subprocess.run([sys.executable, 'direct_migration.py'], 
                          stdout=subprocess.PIPE, 
                          stderr=subprocess.STDOUT,
                          text=True)
    
    # Print all output
    print(result.stdout)
    
    if result.returncode == 0:
        print("\n✓ Migration completed successfully!")
    else:
        print(f"\n✗ Migration failed with return code: {result.returncode}")
        
except Exception as e:
    print(f"Error: {e}")