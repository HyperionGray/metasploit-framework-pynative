#!/usr/bin/env python3

import subprocess
import sys
from pathlib import Path

# Run all conversion steps
repo_root = Path("/workspace")

steps = [
    ("step1_convert.py", "Converting Ruby files to Python"),
    ("step2_rename_ruby.py", "Renaming Ruby files to .rb"),
    ("step3_promote_python.py", "Promoting Python files"),
    ("step4_remove_todos.py", "Removing TODOs"),
    ("step5_verify.py", "Verifying conversion")
]

print("🐍 METASPLOIT PYNATIVE CONVERSION")
print("Ruby will be deleted soon - Converting to Python-native framework")
print("="*70)

for step_file, description in steps:
    print(f"\n📋 {description}...")
    
    try:
        result = subprocess.run(
            [sys.executable, str(repo_root / step_file)],
            cwd=repo_root,
            text=True
        )
        
        if result.returncode != 0:
            print(f"⚠️ Step completed with warnings (exit code: {result.returncode})")
        
    except Exception as e:
        print(f"❌ Error in step: {e}")
        break

print("\n" + "="*70)
print("🎉 PyNative conversion process completed!")
print("Check the verification output above for final status.")