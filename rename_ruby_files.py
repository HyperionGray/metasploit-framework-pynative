#!/usr/bin/env python3

import shutil
from pathlib import Path

# Rename Ruby files to .rb extension
repo_root = Path("/workspace")

print("🐍 Renaming Ruby files to .rb extension...")

# Ruby executables to rename
ruby_files = ["msfconsole", "msfd", "msfdb", "msfrpc", "msfrpcd", "msfupdate", "msfvenom"]

for filename in ruby_files:
    ruby_path = repo_root / filename
    rb_path = repo_root / f"{filename}.rb"
    
    if ruby_path.exists() and not rb_path.exists():
        # Check if it's actually a Ruby file
        try:
            with open(ruby_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                if 'ruby' in first_line.lower():
                    shutil.move(str(ruby_path), str(rb_path))
                    print(f"  ✓ Renamed {filename} -> {filename}.rb")
                else:
                    print(f"  ℹ️ {filename} is not Ruby, skipping")
        except Exception as e:
            print(f"  ❌ Error processing {filename}: {e}")
    elif rb_path.exists():
        print(f"  ℹ️ {filename}.rb already exists")
    else:
        print(f"  ⚠️ {filename} not found")

print("✅ Ruby file renaming completed!")