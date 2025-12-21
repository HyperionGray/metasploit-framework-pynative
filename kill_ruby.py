#!/usr/bin/env python3

# Direct execution of Ruby to Python migration
import sys
import os
from pathlib import Path

# Set up the environment
workspace = Path('/workspace')
os.chdir(workspace)
sys.path.insert(0, str(workspace))

print("🔥 RUBY ELIMINATION IN PROGRESS 🔥")
print("Request: 'kill that ruby. And move to python lets go!!'")
print("=" * 60)

# Import the migration module
try:
    import migrate_ruby_to_python
    print("✅ Migration module loaded")
except Exception as e:
    print(f"❌ Failed to load migration module: {e}")
    sys.exit(1)

# Create and execute migrator
print("🚀 Creating migrator instance...")
migrator = migrate_ruby_to_python.RubyToPythonMigrator(
    workspace_dir=str(workspace),
    dry_run=False,
    verbose=True
)

print("⚡ Executing migration...")
try:
    migrator.migrate_files()
    migrator.print_summary()
    print("\n🎉 RUBY KILLED SUCCESSFULLY! 🎉")
    print("🐍 WELCOME TO THE PYTHON ERA! 🐍")
except Exception as e:
    print(f"❌ Migration failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)