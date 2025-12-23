#!/usr/bin/env python3
"""
Execute Ruby to Python migration - Kill that Ruby!
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🔥 KILLING RUBY AND MOVING TO PYTHON! 🔥")
    print("=" * 60)
    
    # Change to workspace directory
    workspace = Path('/workspace')
    os.chdir(workspace)
    
    # Check if migration script exists
    migration_script = workspace / 'migrate_ruby_to_python.py'
    if not migration_script.exists():
        print(f"❌ Migration script not found: {migration_script}")
        return False
    
    print("✅ Migration script found")
    print("🚀 Starting Ruby elimination process...")
    
    # Execute the migration script
    try:
        # Run with verbose output
        cmd = [sys.executable, str(migration_script), '--verbose']
        print(f"Running: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Print output in real-time
        for line in process.stdout:
            print(line.rstrip())
        
        # Wait for completion
        return_code = process.wait()
        
        if return_code == 0:
            print("\n🎉 RUBY HAS BEEN SUCCESSFULLY KILLED!")
            print("🐍 PYTHON MIGRATION COMPLETE!")
            return True
        else:
            print(f"\n❌ Migration failed with return code: {return_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error executing migration: {e}")
        return False

if __name__ == '__main__':
    success = main()
    if success:
        print("\n" + "="*60)
        print("🎯 MISSION ACCOMPLISHED!")
        print("Ruby has been eliminated from the active codebase!")
        print("Python is now the primary language!")
        print("Legacy Ruby code preserved in legacy/ directory")
        print("="*60)
    else:
        print("\n❌ Mission failed - Ruby still alive!")
    
    sys.exit(0 if success else 1)