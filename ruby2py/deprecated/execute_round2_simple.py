#!/usr/bin/env python3

import subprocess
import sys
import os

os.chdir('/workspace')

print("🐍🔥 ROUND 2: FIGHT! - RUBY vs PYTHON 🔥🐍")
print("=" * 50)

# Run quick check
print("Step 1: Quick inventory...")
subprocess.run([sys.executable, 'quick_check.py'])

print("\nStep 2: Executing migration...")

# Try to run the migration script directly
migration_script = '/workspace/tools/migration/migrate_ruby_to_python.py'

if os.path.exists(migration_script):
    print(f"Found migration script: {migration_script}")
    try:
        # Run with verbose output
        result = subprocess.run([
            sys.executable, migration_script, '--verbose'
        ], cwd='/workspace')
        
        print(f"Migration completed with return code: {result.returncode}")
        
    except Exception as e:
        print(f"Error running migration: {e}")
else:
    print("Migration script not found, running Ruby killer instead...")
    subprocess.run([sys.executable, 'final_ruby_killer.py'])

print("\n🎉 ROUND 2 EXECUTION COMPLETE!")
print("🐍 PYTHON SUPREMACY! 🐍")