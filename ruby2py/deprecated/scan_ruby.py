#!/usr/bin/env python3
import os
from pathlib import Path

workspace = Path("/workspace")
ruby_files = []

print("🔍 Scanning for Ruby files...")

for root, dirs, files in os.walk(workspace):
    # Skip hidden directories
    dirs[:] = [d for d in dirs if not d.startswith('.')]
    
    for file in files:
        if file.endswith('.rb'):
            full_path = Path(root) / file
            ruby_files.append(full_path)

print(f"\nFound {len(ruby_files)} Ruby files:")

for i, rb_file in enumerate(ruby_files):
    rel_path = rb_file.relative_to(workspace)
    size = rb_file.stat().st_size
    print(f"{i+1:3d}. {rel_path} ({size} bytes)")

print(f"\nTotal: {len(ruby_files)} Ruby files found")

# Group by directory
dirs = {}
for rb_file in ruby_files:
    rel_path = rb_file.relative_to(workspace)
    dir_name = str(rel_path.parent)
    if dir_name not in dirs:
        dirs[dir_name] = 0
    dirs[dir_name] += 1

print(f"\nRuby files by directory:")
for dir_name, count in sorted(dirs.items(), key=lambda x: x[1], reverse=True):
    print(f"{count:3d} files in {dir_name}")