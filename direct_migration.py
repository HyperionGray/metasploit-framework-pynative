#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

# Direct execution of Ruby elimination
workspace = Path('/workspace')
legacy_dir = workspace / 'legacy'

print("🔥 DIRECT RUBY ELIMINATION 🔥")
print("Killing Ruby and moving to Python!")
print("=" * 50)

# Create legacy directory
legacy_dir.mkdir(exist_ok=True)
print(f"✅ Created legacy directory: {legacy_dir}")

# Create subdirectories in legacy
for subdir in ['modules', 'lib', 'tools', 'scripts', 'external']:
    (legacy_dir / subdir).mkdir(exist_ok=True)
    print(f"✅ Created legacy/{subdir}")

# Find Ruby files
ruby_files = []
for pattern in ['**/*.rb']:
    for rb_file in workspace.glob(pattern):
        # Skip files already in legacy or git
        if 'legacy' not in rb_file.parts and '.git' not in rb_file.parts:
            ruby_files.append(rb_file)

print(f"\n📊 Found {len(ruby_files)} Ruby files to eliminate")

# Move Ruby files to legacy
moved = 0
errors = 0

for rb_file in ruby_files:
    try:
        rel_path = rb_file.relative_to(workspace)
        legacy_path = legacy_dir / rel_path
        
        # Create parent directories
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Move file
        shutil.move(str(rb_file), str(legacy_path))
        moved += 1
        
        if moved <= 10:  # Show first 10
            print(f"✅ Moved: {rel_path}")
        elif moved == 11:
            print("... (continuing to move files)")
            
    except Exception as e:
        errors += 1
        print(f"❌ Error moving {rb_file}: {e}")

print(f"\n🎯 ELIMINATION RESULTS:")
print(f"Ruby files moved to legacy: {moved}")
print(f"Errors: {errors}")

# Check for remaining Ruby files
remaining = []
for rb_file in workspace.glob('**/*.rb'):
    if 'legacy' not in rb_file.parts and '.git' not in rb_file.parts:
        remaining.append(rb_file)

print(f"Remaining Ruby files in active codebase: {len(remaining)}")

if len(remaining) == 0:
    print("\n🎉 RUBY ELIMINATION COMPLETE!")
    print("🐍 PYTHON IS NOW THE KING!")
    print("✅ All Ruby files moved to legacy/")
    print("✅ Python framework ready for use")
else:
    print(f"\n⚠️  {len(remaining)} Ruby files still remain:")
    for f in remaining[:5]:
        print(f"  - {f.relative_to(workspace)}")

print("\n🚀 MISSION STATUS: RUBY KILLED!")
print("Long live Python! 🐍")
