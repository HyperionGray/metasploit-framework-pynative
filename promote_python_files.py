#!/usr/bin/env python3

import shutil
import os
from pathlib import Path

# Promote Python files by removing .py extension
repo_root = Path("/workspace")

print("🐍 Promoting Python files (removing .py extensions)...")

# Python executables to promote
python_files = ["msfconsole.py", "msfd.py", "msfdb.py", "msfrpc.py", "msfrpcd.py", "msfupdate.py", "msfvenom.py"]

for filename in python_files:
    py_path = repo_root / filename
    target_name = filename[:-3]  # Remove .py
    target_path = repo_root / target_name
    
    if py_path.exists():
        if target_path.exists():
            print(f"  ⚠️ {target_name} exists, backing up to {target_name}.bak")
            backup_path = repo_root / f"{target_name}.bak"
            shutil.move(str(target_path), str(backup_path))
        
        # Move Python file to become primary executable
        shutil.move(str(py_path), str(target_path))
        
        # Make executable
        os.chmod(target_path, 0o755)
        
        print(f"  ✓ Promoted {filename} -> {target_name}")
    else:
        print(f"  ⚠️ {filename} not found")

print("✅ Python file promotion completed!")