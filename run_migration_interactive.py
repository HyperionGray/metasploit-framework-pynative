#!/usr/bin/env python3

import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

print("Ruby to Python Migration - Round 5: FIGHT!")
print("=" * 50)

# Run the migration executor
try:
    result = subprocess.run([
        sys.executable, 'execute_ruby_to_python_migration.py', '--dry-run'
    ], capture_output=False, text=True)
    
    if result.returncode == 0:
        print("\nDry run completed successfully!")
        
        # Ask user if they want to proceed
        response = input("\nProceed with actual migration? (y/N): ").strip().lower()
        
        if response in ['y', 'yes']:
            print("\nExecuting actual migration...")
            result = subprocess.run([
                sys.executable, 'execute_ruby_to_python_migration.py'
            ], capture_output=False, text=True)
            
            if result.returncode == 0:
                print("\nMigration completed successfully!")
            else:
                print("\nMigration failed!")
        else:
            print("Migration cancelled by user.")
    else:
        print("Dry run failed!")
        
except Exception as e:
    print(f"Error running migration: {e}")