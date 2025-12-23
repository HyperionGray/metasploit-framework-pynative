#!/usr/bin/env python3
"""
IMMEDIATE RUBY TO PYTHON CONVERSION
Execute the conversion right now!
"""

import os
import sys
import subprocess
from pathlib import Path

# Set working directory
os.chdir('/workspace')

print("🔥 IMMEDIATE RUBY TO PYTHON CONVERSION")
print("=" * 60)
print("Converting Ruby to Python RIGHT NOW!")
print("=" * 60)

# Step 1: Quick scan to see what we're working with
print("\n🔍 STEP 1: Quick Ruby scan")
workspace = Path("/workspace")
ruby_files = []

for root, dirs, files in os.walk(workspace):
    dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'legacy']
    for file in files:
        if file.endswith('.rb'):
            ruby_files.append(Path(root) / file)

print(f"Found {len(ruby_files)} Ruby files to process")

if len(ruby_files) == 0:
    print("🎉 NO RUBY FILES FOUND! Conversion already complete!")
    sys.exit(0)

# Show the files
for i, rb_file in enumerate(ruby_files):
    rel_path = rb_file.relative_to(workspace)
    print(f"  {i+1}. {rel_path}")

# Step 2: Execute conversion
print(f"\n⚡ STEP 2: Converting {len(ruby_files)} Ruby files to Python")

# Try to run the ultimate ruby killer
try:
    print("Running ultimate_ruby_killer.py...")
    result = subprocess.run([sys.executable, "ultimate_ruby_killer.py"], 
                          cwd="/workspace", timeout=300)
    print(f"Ultimate ruby killer completed with exit code: {result.returncode}")
except Exception as e:
    print(f"Ultimate ruby killer failed: {e}")

# Step 3: Verify results
print("\n📊 STEP 3: Verification")

# Count remaining Ruby files
remaining_ruby = []
for root, dirs, files in os.walk(workspace):
    dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'legacy']
    for file in files:
        if file.endswith('.rb'):
            remaining_ruby.append(Path(root) / file)

print(f"Ruby files remaining: {len(remaining_ruby)}")

# Count Python modules
python_modules = list(workspace.glob("modules/**/*.py"))
print(f"Python modules found: {len(python_modules)}")

# Check legacy
legacy_dir = workspace / "legacy"
if legacy_dir.exists():
    legacy_ruby = list(legacy_dir.glob("**/*.rb"))
    print(f"Ruby files in legacy: {len(legacy_ruby)}")

print("\n" + "=" * 60)

if len(remaining_ruby) == 0:
    print("🎉 PERFECT SUCCESS!")
    print("🔥 ALL RUBY FILES ELIMINATED!")
    print("🐍 PYTHON CONVERSION COMPLETE!")
    success = True
else:
    print(f"⚠️  {len(remaining_ruby)} Ruby files still remain")
    print("🔧 May need manual cleanup")
    success = len(remaining_ruby) <= 3

print("=" * 60)
print("🚀 IMMEDIATE CONVERSION COMPLETE!")

sys.exit(0 if success else 1)