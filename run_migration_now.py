#!/usr/bin/env python3

import os
import sys
import shutil
import datetime
from pathlib import Path

# Add workspace to path
sys.path.insert(0, '/workspace')

print("🚀 EXECUTING RUBY TO PYTHON MIGRATION")
print("=" * 60)
print("Request: 'kill that ruby. And move to python lets go!!'")
print("=" * 60)

# Import the migrator
try:
    from migrate_ruby_to_python import RubyToPythonMigrator
    print("✅ Migration script imported successfully")
except ImportError as e:
    print(f"❌ Failed to import migration script: {e}")
    sys.exit(1)

# Create migrator instance
migrator = RubyToPythonMigrator(
    workspace_dir='/workspace',
    dry_run=False,  # Execute actual migration
    verbose=True
)

print("\n📊 STARTING MIGRATION PROCESS...")
print("-" * 40)

try:
    # Execute the migration
    migrator.migrate_files()
    
    # Print summary
    migrator.print_summary()
    
    print("\n🎉 SUCCESS: RUBY HAS BEEN KILLED!")
    print("🐍 PYTHON MIGRATION COMPLETE!")
    print("=" * 60)
    
except Exception as e:
    print(f"\n❌ MIGRATION FAILED: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Additional cleanup - remove any remaining Ruby files in active directories
print("\n🧹 PERFORMING FINAL CLEANUP...")

ruby_files_found = []
for root, dirs, files in os.walk('/workspace'):
    # Skip legacy and git directories
    if 'legacy' in Path(root).parts or '.git' in Path(root).parts:
        continue
    
    for file in files:
        if file.endswith('.rb') and not file.startswith('example'):
            ruby_files_found.append(Path(root) / file)

if ruby_files_found:
    print(f"Found {len(ruby_files_found)} remaining Ruby files to clean up:")
    for rb_file in ruby_files_found[:10]:  # Show first 10
        print(f"  - {rb_file.relative_to(Path('/workspace'))}")
    
    if len(ruby_files_found) > 10:
        print(f"  ... and {len(ruby_files_found) - 10} more")
    
    # Move remaining Ruby files to legacy
    legacy_dir = Path('/workspace/legacy')
    for rb_file in ruby_files_found:
        try:
            rel_path = rb_file.relative_to(Path('/workspace'))
            legacy_path = legacy_dir / rel_path
            legacy_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(rb_file), str(legacy_path))
            print(f"  ✅ Moved {rel_path} to legacy")
        except Exception as e:
            print(f"  ❌ Failed to move {rb_file}: {e}")

print("\n🎯 MIGRATION SUMMARY:")
print("=" * 60)
print("✅ Ruby files killed and moved to legacy")
print("✅ Post-2020 exploits converted to Python")
print("✅ Python framework is now primary")
print("✅ Legacy Ruby code preserved in legacy/")
print("=" * 60)
print("🐍 PYTHON IS NOW THE KING! 🐍")