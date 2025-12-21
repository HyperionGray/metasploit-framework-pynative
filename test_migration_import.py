#!/usr/bin/env python3
import sys
import os
from pathlib import Path

# Change to workspace
os.chdir("/workspace")
sys.path.insert(0, "/workspace")

print("Testing migration script import...")

try:
    from migrate_ruby_to_python import RubyToPythonMigrator
    print("✅ Successfully imported RubyToPythonMigrator")
    
    # Test creating an instance
    migrator = RubyToPythonMigrator(dry_run=True, verbose=True)
    print("✅ Successfully created migrator instance")
    
    # Find some Ruby files
    workspace = Path("/workspace")
    ruby_files = list(workspace.rglob("*.rb"))
    
    # Filter out test/spec/legacy files
    filtered_files = []
    for rb_file in ruby_files:
        if not any(skip in str(rb_file) for skip in ['legacy', 'spec', 'test', '.git']):
            filtered_files.append(rb_file)
    
    print(f"Found {len(filtered_files)} Ruby files to potentially convert")
    
    if filtered_files:
        print("Sample files:")
        for i, rb_file in enumerate(filtered_files[:5]):
            rel_path = rb_file.relative_to(workspace)
            print(f"  {i+1}. {rel_path}")
    
    print("✅ Ready to run migration!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()