#!/usr/bin/env python3
"""
Direct execution of Python Round 2 migration
"""

import os
import sys
from pathlib import Path

# Change to workspace directory
os.chdir("/workspace")

# Import and run the migrator
sys.path.insert(0, '/workspace')

try:
    from migrate_ruby_to_python import RubyToPythonMigrator
    
    print("🐍 PYTHON ROUND 2: GRAB ALL THE RUBY AND PYTHON IT! 🐍")
    print("=" * 60)
    
    # First, let's see what we're working with
    workspace = Path("/workspace")
    ruby_files = []
    
    # Find Ruby files in key directories
    key_dirs = ["modules/exploits", "modules/auxiliary", "modules/post", "lib", "tools", "scripts"]
    
    for dir_name in key_dirs:
        dir_path = workspace / dir_name
        if dir_path.exists():
            for rb_file in dir_path.rglob("*.rb"):
                if "legacy" not in str(rb_file) and "spec" not in str(rb_file) and "test" not in str(rb_file):
                    ruby_files.append(rb_file)
    
    print(f"Found {len(ruby_files)} Ruby files to process")
    
    if len(ruby_files) == 0:
        print("No Ruby files found to convert. Migration may already be complete!")
        sys.exit(0)
    
    # Show some examples
    print("\nSample Ruby files to convert:")
    for i, rb_file in enumerate(ruby_files[:10]):
        rel_path = rb_file.relative_to(workspace)
        print(f"  {i+1:2d}. {rel_path}")
    
    if len(ruby_files) > 10:
        print(f"  ... and {len(ruby_files) - 10} more files")
    
    # Run the migration
    print(f"\n=== STARTING MIGRATION ===")
    
    migrator = RubyToPythonMigrator(
        workspace_dir="/workspace",
        dry_run=False,  # Actually do the conversion
        verbose=True
    )
    
    migrator.migrate_files()
    migrator.print_summary()
    
    print("\n🎉 PYTHON ROUND 2 COMPLETE! 🎉")
    print("Ruby files have been PYTHON-ed as requested!")
    
except ImportError as e:
    print(f"Could not import migration script: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Migration failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)