#!/usr/bin/env python3
"""
Execute the Ruby to Python migration
"""
import sys
import os
sys.path.insert(0, '/workspace')

# Import and run the migration
from migrate_ruby_to_python import RubyToPythonMigrator

def main():
    print("=== RUBY TO PYTHON MIGRATION EXECUTION ===")
    print("Executing the migration to 'kill that ruby' and move to Python!")
    print()
    
    # First, run a dry-run to see what would happen
    print("1. Running dry-run to preview changes...")
    migrator_dry = RubyToPythonMigrator(
        workspace_dir='/workspace',
        dry_run=True,
        verbose=True
    )
    
    try:
        migrator_dry.migrate_files()
        migrator_dry.print_summary()
    except Exception as e:
        print(f"Dry-run failed: {e}")
        return False
    
    print("\n" + "="*60)
    print("DRY-RUN COMPLETED - Now executing actual migration...")
    print("="*60)
    
    # Now run the actual migration
    print("2. Executing actual migration...")
    migrator = RubyToPythonMigrator(
        workspace_dir='/workspace',
        dry_run=False,
        verbose=True
    )
    
    try:
        migrator.migrate_files()
        migrator.print_summary()
        print("\n🎉 RUBY HAS BEEN KILLED! PYTHON MIGRATION COMPLETE! 🎉")
        return True
    except Exception as e:
        print(f"Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)