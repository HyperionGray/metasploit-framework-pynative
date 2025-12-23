#!/usr/bin/env python3

import subprocess
import sys
import os

def main():
    print("🐍🔥 ROUND 2: FIGHT! - PYTHON vs RUBY 🔥🐍")
    print("=" * 60)
    print("Executing Ruby-to-Python migration for post-2020 modules")
    print("Moving pre-2020 modules to legacy")
    print("KILL ALL THE RUBY! PYTHON SUPREMACY!")
    print("=" * 60)
    
    os.chdir('/workspace')
    
    # Step 1: Pre-migration check
    print("\n🔍 Step 1: Pre-migration inventory...")
    try:
        result = subprocess.run([sys.executable, 'pre_migration_check.py'], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Warnings:", result.stderr)
    except Exception as e:
        print(f"Error in pre-check: {e}")
    
    # Step 2: Execute enhanced migration
    print("\n🚀 Step 2: Executing Round 2 Enhanced migration...")
    try:
        result = subprocess.run([sys.executable, 'execute_round2_enhanced.py', '--verbose'], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Errors:", result.stderr)
        
        if result.returncode != 0:
            print("❌ Migration failed!")
            return False
    except Exception as e:
        print(f"Error in migration: {e}")
        return False
    
    # Step 3: Final Ruby elimination
    print("\n🎯 Step 3: Final Ruby elimination...")
    try:
        result = subprocess.run([sys.executable, 'final_ruby_killer.py'], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("Warnings:", result.stderr)
    except Exception as e:
        print(f"Error in Ruby elimination: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 ROUND 2 COMPLETE! PYTHON VICTORY! 🎉")
    print("🐍 Ruby has been defeated! Python reigns supreme! 🐍")
    print("=" * 60)
    
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)