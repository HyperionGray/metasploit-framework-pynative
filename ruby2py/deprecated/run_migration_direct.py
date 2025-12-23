#!/usr/bin/env python3
"""
Run the migration directly by executing the script
"""
import subprocess
import sys
import os

def main():
    print("🐍 PYTHON ROUND 2: EXECUTING MIGRATION 🐍")
    print("=" * 50)
    
    os.chdir("/workspace")
    
    # First run a dry-run to see what would happen
    print("Step 1: Running dry-run to preview changes...")
    try:
        result = subprocess.run([
            sys.executable, "/workspace/migrate_ruby_to_python.py", 
            "--dry-run", "--verbose"
        ], capture_output=True, text=True, cwd="/workspace")
        
        print("DRY-RUN OUTPUT:")
        print(result.stdout)
        if result.stderr:
            print("DRY-RUN STDERR:")
            print(result.stderr)
        
        if result.returncode != 0:
            print("❌ Dry-run failed!")
            return False
            
    except Exception as e:
        print(f"❌ Error running dry-run: {e}")
        return False
    
    # Now run the actual migration
    print("\nStep 2: Running actual migration...")
    try:
        result = subprocess.run([
            sys.executable, "/workspace/migrate_ruby_to_python.py", 
            "--verbose"
        ], capture_output=True, text=True, cwd="/workspace")
        
        print("MIGRATION OUTPUT:")
        print(result.stdout)
        if result.stderr:
            print("MIGRATION STDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("✅ Migration completed successfully!")
            return True
        else:
            print("❌ Migration failed!")
            return False
            
    except Exception as e:
        print(f"❌ Error running migration: {e}")
        return False

if __name__ == "__main__":
    success = main()
    if success:
        print("\n🎉 PYTHON ROUND 2 COMPLETE! 🎉")
        print("All Ruby has been PYTHON-ed!")
    else:
        print("\n❌ Migration failed. Check errors above.")
    
    sys.exit(0 if success else 1)