#!/usr/bin/env python3

import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

print("Executing Ruby to Python Migration...")
print("=" * 45)

try:
    # Run the migration script and capture output
    result = subprocess.run([
        sys.executable, 'final_migration_exec.py'
    ], capture_output=True, text=True, timeout=300)
    
    # Print the output
    if result.stdout:
        print("MIGRATION OUTPUT:")
        print("-" * 20)
        print(result.stdout)
    
    if result.stderr:
        print("\nERRORS/WARNINGS:")
        print("-" * 20)
        print(result.stderr)
    
    print(f"\nReturn code: {result.returncode}")
    
    if result.returncode == 0:
        print("✅ Migration completed successfully!")
    else:
        print("❌ Migration failed!")
        
except subprocess.TimeoutExpired:
    print("❌ Migration timed out!")
except Exception as e:
    print(f"❌ Error running migration: {e}")

print("\nMigration execution finished.")