#!/usr/bin/env python3
"""
Quick Ruby to Python migration execution
"""
import os
import sys
import subprocess

def run_migration():
    """Run the Ruby to Python migration"""
    print("🚀 STARTING RUBY TO PYTHON MIGRATION")
    print("=" * 50)
    
    # Change to workspace directory
    os.chdir('/workspace')
    
    # Run the migration script
    try:
        print("Running migration script...")
        result = subprocess.run([
            sys.executable, 'migrate_ruby_to_python.py', '--verbose'
        ], capture_output=True, text=True, timeout=300)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
        
        if result.returncode == 0:
            print("\n🎉 MIGRATION COMPLETED SUCCESSFULLY!")
            print("Ruby has been killed! Python migration complete!")
        else:
            print(f"\n❌ Migration failed with return code: {result.returncode}")
            
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print("❌ Migration timed out after 5 minutes")
        return False
    except Exception as e:
        print(f"❌ Migration failed with error: {e}")
        return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)