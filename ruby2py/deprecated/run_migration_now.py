#!/usr/bin/env python3

import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

print("Executing Ruby to Python Migration - Round 5: FIGHT!")
print("=" * 55)

try:
    # Execute the migration script
    result = subprocess.run([
        sys.executable, 'ruby_to_python_migration.py'
    ], text=True)
    
    if result.returncode == 0:
        print("\n🎉 Migration completed successfully!")
    else:
        print(f"\n❌ Migration failed with return code: {result.returncode}")
        
except Exception as e:
    print(f"❌ Error executing migration: {e}")
    
print("\nMigration execution finished.")