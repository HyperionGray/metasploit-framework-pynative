#!/usr/bin/env python3

import os
import shutil
from pathlib import Path

# Step 3: Promote Python files (remove .py extensions)
repo_root = Path("/workspace")

print("🐍 STEP 3: Promoting Python files (removing .py extensions)")
print("="*70)

# Key Python executables to promote
python_executables = [
    "msfconsole.py",
    "msfd.py", 
    "msfdb.py",
    "msfrpc.py",
    "msfrpcd.py",
    "msfupdate.py",
    "msfvenom.py"
]

promoted_count = 0

for executable in python_executables:
    py_file = repo_root / executable
    if py_file.exists():
        # Target name without .py extension
        target_name = executable[:-3]  # Remove .py
        target_path = repo_root / target_name
        
        # Check if target already exists
        if target_path.exists():
            print(f"  ⚠️ Target exists, backing up: {target_name}")
            backup_path = target_path.with_suffix('.rb.bak')
            shutil.move(str(target_path), str(backup_path))
        
        # Move Python file to become the primary executable
        shutil.move(str(py_file), str(target_path))
        
        # Make sure it's executable
        os.chmod(target_path, 0o755)
        
        print(f"  ✓ Promoted: {executable} -> {target_name}")
        promoted_count += 1
    else:
        print(f"  ⚠️ {executable} not found")

print(f"✅ Step 3 completed - Promoted {promoted_count} Python files to primary executables")