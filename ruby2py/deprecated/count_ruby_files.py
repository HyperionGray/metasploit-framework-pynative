#!/usr/bin/env python3
import os
from pathlib import Path

workspace = Path("/workspace")
ruby_count = 0
python_count = 0

# Count files in key directories
for root, dirs, files in os.walk(workspace):
    # Skip certain directories
    if any(skip in root for skip in ['legacy', '.git', 'spec', 'test', 'vendor']):
        continue
    
    for file in files:
        if file.endswith('.rb'):
            ruby_count += 1
        elif file.endswith('.py'):
            python_count += 1

print(f"Current file counts:")
print(f"Ruby files (.rb): {ruby_count}")
print(f"Python files (.py): {python_count}")

# Check specific exploit directory
exploits_dir = workspace / "modules" / "exploits" / "linux" / "http"
if exploits_dir.exists():
    rb_files = list(exploits_dir.glob("*.rb"))
    py_files = list(exploits_dir.glob("*.py"))
    print(f"\nIn modules/exploits/linux/http:")
    print(f"Ruby files: {len(rb_files)}")
    print(f"Python files: {len(py_files)}")
    
    if rb_files:
        print(f"First few Ruby files to convert:")
        for i, rb_file in enumerate(rb_files[:5]):
            print(f"  {i+1}. {rb_file.name}")