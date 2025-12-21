#!/usr/bin/env python3
import os
import subprocess
from pathlib import Path

# Find all .rb files in the workspace
def find_ruby_files():
    workspace = Path("/workspace")
    ruby_files = []
    
    for root, dirs, files in os.walk(workspace):
        # Skip .git and other hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        
        for file in files:
            if file.endswith('.rb'):
                full_path = Path(root) / file
                ruby_files.append(full_path)
    
    return ruby_files

print("🔍 Searching for Ruby files in the workspace...")
ruby_files = find_ruby_files()

print(f"Found {len(ruby_files)} Ruby files:")
for i, rb_file in enumerate(ruby_files[:20]):  # Show first 20
    rel_path = rb_file.relative_to(Path("/workspace"))
    print(f"{i+1:2d}. {rel_path}")

if len(ruby_files) > 20:
    print(f"... and {len(ruby_files) - 20} more files")

# Group by directory
dirs = {}
for rb_file in ruby_files:
    rel_path = rb_file.relative_to(Path("/workspace"))
    dir_name = str(rel_path.parent)
    if dir_name not in dirs:
        dirs[dir_name] = 0
    dirs[dir_name] += 1

print(f"\nRuby files by directory:")
for dir_name, count in sorted(dirs.items(), key=lambda x: x[1], reverse=True)[:15]:
    print(f"{count:3d} files in {dir_name}")