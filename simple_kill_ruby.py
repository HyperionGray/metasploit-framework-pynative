#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

print("🔥 KILLING RUBY - SIMPLE APPROACH 🔥")
print("=" * 50)

workspace = Path('/workspace')
legacy_dir = workspace / 'legacy'

# Create legacy directory
legacy_dir.mkdir(exist_ok=True)
(legacy_dir / 'modules').mkdir(exist_ok=True)

# Find Ruby files in modules
ruby_files = list(workspace.glob('modules/**/*.rb'))
print(f"Found {len(ruby_files)} Ruby files in modules/")

moved_count = 0
for rb_file in ruby_files:
    try:
        rel_path = rb_file.relative_to(workspace)
        legacy_path = legacy_dir / rel_path
        legacy_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Move to legacy
        shutil.move(str(rb_file), str(legacy_path))
        moved_count += 1
        print(f"✅ Moved: {rel_path}")
        
    except Exception as e:
        print(f"❌ Error moving {rb_file}: {e}")

print(f"\n🎯 RESULTS:")
print(f"Ruby files moved to legacy: {moved_count}")
print("🎉 RUBY KILLED IN MODULES DIRECTORY!")
print("🐍 Python framework is now primary!")

# Check remaining Ruby files
remaining = list(workspace.glob('**/*.rb'))
remaining = [f for f in remaining if 'legacy' not in f.parts and '.git' not in f.parts]
print(f"\nRemaining Ruby files: {len(remaining)}")

if remaining:
    print("Remaining files:")
    for f in remaining[:10]:
        print(f"  - {f.relative_to(workspace)}")