#!/usr/bin/env python3

# Execute the migration directly
import subprocess
import sys
import os

os.chdir('/workspace')

print("Executing Ruby to Python Migration...")
print("=" * 45)

try:
    # Execute the migration script
    process = subprocess.Popen([
        sys.executable, 'execute_migration_now.py'
    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
       universal_newlines=True, bufsize=1)
    
    # Print output in real-time
    for line in process.stdout:
        print(line.rstrip())
    
    process.wait()
    
    print(f"\nMigration completed with return code: {process.returncode}")
    
    if process.returncode == 0:
        print("✅ Migration successful!")
    else:
        print("❌ Migration failed!")
        
except Exception as e:
    print(f"❌ Error: {e}")

print("\nDone.")