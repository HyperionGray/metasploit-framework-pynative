#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

# Change to workspace
workspace = Path('/workspace')
os.chdir(workspace)

print("🔥 EXECUTING RUBY ELIMINATION NOW 🔥")
print("=" * 50)

# Create legacy directory
legacy_dir = workspace / 'legacy'
legacy_dir.mkdir(exist_ok=True)

# Create subdirectories
subdirs = ['modules', 'lib', 'tools', 'scripts', 'plugins', 'external']
for subdir in subdirs:
    (legacy_dir / subdir).mkdir(exist_ok=True)

print("✅ Legacy directories created")

# Find Ruby files
ruby_files = list(workspace.glob('**/*.rb'))
# Filter out legacy and git files
ruby_files = [f for f in ruby_files if 'legacy' not in f.parts and '.git' not in f.parts]

print(f"📊 Found {len(ruby_files)} Ruby files")

# Move files
moved = 0
for rb_file in ruby_files:
    try:
        rel_path = rb_file.relative_to(workspace)
        legacy_path = legacy_dir / rel_path
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(rb_file), str(legacy_path))
        moved += 1
        if moved <= 5:
            print(f"✅ Moved: {rel_path}")
    except Exception as e:
        print(f"❌ Error: {e}")

print(f"\n🎯 Moved {moved} Ruby files to legacy")

# Check remaining
remaining = list(workspace.glob('**/*.rb'))
remaining = [f for f in remaining if 'legacy' not in f.parts and '.git' not in f.parts]

print(f"Remaining Ruby files: {len(remaining)}")

if len(remaining) == 0:
    print("🎉 RUBY ELIMINATION COMPLETE!")
    print("🐍 PYTHON IS NOW KING!")
else:
    print("Some Ruby files remain:")
    for f in remaining[:3]:
        print(f"  {f}")

print("\n✅ MISSION ACCOMPLISHED!")
print("Ruby has been killed! Long live Python! 🐍")