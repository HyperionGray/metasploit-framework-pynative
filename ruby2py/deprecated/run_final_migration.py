#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

# Change to workspace directory
os.chdir('/workspace')

print("Ruby to Python Migration - Round 5: FIGHT!")
print("=" * 50)

# Execute the final migration script
try:
    result = subprocess.run([sys.executable, 'final_migration.py'], 
                          capture_output=False, text=True)
    
    if result.returncode == 0:
        print("\nMigration script completed successfully!")
    else:
        print(f"\nMigration script failed with return code: {result.returncode}")
        
except Exception as e:
    print(f"Error running migration: {e}")