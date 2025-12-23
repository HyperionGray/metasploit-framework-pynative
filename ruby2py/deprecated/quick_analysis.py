#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Change to workspace directory
os.chdir('/workspace')

print("Quick Ruby File Analysis")
print("=" * 30)

# Count Ruby files in different directories
workspace = Path('/workspace')

# Check modules directory
modules_dir = workspace / 'modules'
if modules_dir.exists():
    ruby_files = list(modules_dir.rglob('*.rb'))
    print(f"Ruby files in modules/: {len(ruby_files)}")
    
    # Show some examples
    if ruby_files:
        print("\nSample Ruby files:")
        for i, rb_file in enumerate(ruby_files[:10]):
            rel_path = rb_file.relative_to(workspace)
            print(f"  {rel_path}")
        if len(ruby_files) > 10:
            print(f"  ... and {len(ruby_files) - 10} more")

# Check lib directory
lib_dir = workspace / 'lib'
if lib_dir.exists():
    lib_ruby_files = list(lib_dir.rglob('*.rb'))
    print(f"\nRuby files in lib/: {len(lib_ruby_files)}")

# Check if OLD or legacy directories exist
old_dir = workspace / 'OLD'
legacy_dir = workspace / 'legacy'

print(f"\nDirectory status:")
print(f"  OLD/ exists: {old_dir.exists()}")
print(f"  legacy/ exists: {legacy_dir.exists()}")

if legacy_dir.exists():
    legacy_files = list(legacy_dir.rglob('*.rb'))
    print(f"  Ruby files in legacy/: {len(legacy_files)}")

# Check Python files in modules
python_files = list(modules_dir.rglob('*.py')) if modules_dir.exists() else []
print(f"\nPython files in modules/: {len(python_files)}")

print(f"\nTotal analysis:")
print(f"  Ruby files to potentially migrate: {len(ruby_files) if 'ruby_files' in locals() else 0}")
print(f"  Python files already present: {len(python_files)}")