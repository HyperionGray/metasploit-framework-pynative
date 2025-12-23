#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

repo_root = Path("/workspace")

print("🐍 METASPLOIT PYNATIVE CONVERSION")
print("Ruby will be deleted soon - Converting to Python-native framework")
print("="*70)

# Step 1: Rename Ruby files
print("\n📋 Step 1: Renaming Ruby files to .rb extension...")
try:
    subprocess.run([sys.executable, str(repo_root / "rename_ruby_files.py")], cwd=repo_root, check=True)
except Exception as e:
    print(f"❌ Error in step 1: {e}")

# Step 2: Promote Python files  
print("\n📋 Step 2: Promoting Python files...")
try:
    subprocess.run([sys.executable, str(repo_root / "promote_python_files.py")], cwd=repo_root, check=True)
except Exception as e:
    print(f"❌ Error in step 2: {e}")

print("\n" + "="*70)
print("🎉 Basic file restructuring completed!")
print("Now checking results...")