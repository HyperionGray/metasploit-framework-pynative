#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

# Step 2: Rename Ruby files to .rb extension
repo_root = Path("/workspace")

print("🐍 STEP 2: Renaming Ruby files to .rb extension")
print("="*70)

# Key Ruby executables to rename
ruby_executables = [
    "msfconsole",
    "msfd", 
    "msfdb",
    "msfrpc",
    "msfrpcd",
    "msfupdate",
    "msfvenom"
]

renamed_count = 0

for executable in ruby_executables:
    ruby_file = repo_root / executable
    if ruby_file.exists():
        try:
            # Check if it's a Ruby file
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
                if 'ruby' in first_line.lower():
                    # Rename to .rb
                    rb_file = ruby_file.with_suffix('.rb')
                    if not rb_file.exists():
                        shutil.move(str(ruby_file), str(rb_file))
                        print(f"  ✓ Renamed: {executable} -> {executable}.rb")
                        renamed_count += 1
                    else:
                        print(f"  ⚠️ Target exists, skipping: {executable}.rb")
                else:
                    print(f"  ℹ️ {executable} is not a Ruby file, skipping")
        except Exception as e:
            print(f"  ❌ Could not process {executable}: {e}")
    else:
        print(f"  ⚠️ {executable} not found")

print(f"✅ Step 2 completed - Renamed {renamed_count} Ruby files to .rb extension")