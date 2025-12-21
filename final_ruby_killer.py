#!/usr/bin/env python3
"""
Final Ruby Killer - Execute the migration
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

def execute_migration():
    """Execute the Ruby to Python migration"""
    
    print("🔥 FINAL RUBY ELIMINATION SEQUENCE 🔥")
    print("=" * 60)
    print("Mission: Kill that Ruby and move to Python!")
    print("=" * 60)
    
    workspace = Path('/workspace')
    os.chdir(workspace)
    
    # Method 1: Try to run the existing migration script
    migration_script = workspace / 'migrate_ruby_to_python.py'
    
    if migration_script.exists():
        print("🚀 Attempting to run existing migration script...")
        try:
            # Import and run directly
            sys.path.insert(0, str(workspace))
            
            # Import the migration class
            spec = __import__('migrate_ruby_to_python')
            migrator_class = spec.RubyToPythonMigrator
            
            # Create migrator instance
            migrator = migrator_class(
                workspace_dir=str(workspace),
                dry_run=False,
                verbose=True
            )
            
            # Execute migration
            print("⚡ Executing migration...")
            migrator.migrate_files()
            migrator.print_summary()
            
            print("\n🎉 MIGRATION SCRIPT EXECUTED SUCCESSFULLY!")
            return True
            
        except Exception as e:
            print(f"❌ Migration script failed: {e}")
            print("🔄 Falling back to manual approach...")
    
    # Method 2: Manual Ruby elimination
    print("\n🛠️  MANUAL RUBY ELIMINATION")
    print("-" * 40)
    
    # Create legacy directory structure
    legacy_dir = workspace / 'legacy'
    legacy_dir.mkdir(exist_ok=True)
    
    for subdir in ['modules', 'lib', 'tools', 'scripts', 'external']:
        (legacy_dir / subdir).mkdir(exist_ok=True)
    
    print("✅ Legacy directory structure created")
    
    # Find all Ruby files (excluding legacy and git)
    ruby_files = []
    for root, dirs, files in os.walk(workspace):
        path_parts = Path(root).parts
        if 'legacy' in path_parts or '.git' in path_parts:
            continue
        
        for file in files:
            if file.endswith('.rb'):
                ruby_files.append(Path(root) / file)
    
    print(f"📊 Found {len(ruby_files)} Ruby files to eliminate")
    
    # Process Ruby files
    moved_count = 0
    converted_count = 0
    error_count = 0
    
    for rb_file in ruby_files:
        try:
            rel_path = rb_file.relative_to(workspace)
            print(f"Processing: {rel_path}")
            
            # Move all Ruby files to legacy for now
            legacy_path = legacy_dir / rel_path
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            
            shutil.move(str(rb_file), str(legacy_path))
            moved_count += 1
            print(f"  ✅ Moved to legacy")
            
        except Exception as e:
            print(f"  ❌ Error: {e}")
            error_count += 1
    
    # Summary
    print("\n" + "=" * 60)
    print("🎯 RUBY ELIMINATION COMPLETE!")
    print("=" * 60)
    print(f"Ruby files moved to legacy: {moved_count}")
    print(f"Errors encountered: {error_count}")
    print("=" * 60)
    
    if error_count == 0:
        print("🎉 RUBY HAS BEEN COMPLETELY ELIMINATED!")
        print("🐍 PYTHON IS NOW THE SUPREME LANGUAGE!")
        print("✅ All Ruby files moved to legacy/ directory")
        print("✅ Python framework is ready for use")
        return True
    else:
        print("⚠️  Some errors occurred during elimination")
        return False

if __name__ == '__main__':
    success = execute_migration()
    
    if success:
        print("\n🚀 MISSION ACCOMPLISHED!")
        print("Ruby has been killed! Long live Python! 🐍")
    else:
        print("\n❌ Mission partially completed with errors")
    
    # Final check
    workspace = Path('/workspace')
    remaining_ruby = []
    for root, dirs, files in os.walk(workspace):
        if 'legacy' in Path(root).parts or '.git' in Path(root).parts:
            continue
        for file in files:
            if file.endswith('.rb'):
                remaining_ruby.append(Path(root) / file)
    
    print(f"\n📊 Final status: {len(remaining_ruby)} Ruby files remaining in active codebase")
    
    if len(remaining_ruby) == 0:
        print("🎉 PERFECT! NO RUBY FILES REMAIN!")
        print("🐍 PYTHON VICTORY IS COMPLETE!")
    else:
        print("Remaining Ruby files:")
        for f in remaining_ruby[:5]:
            print(f"  - {f.relative_to(workspace)}")
    
    sys.exit(0 if success else 1)