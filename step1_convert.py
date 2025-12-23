#!/usr/bin/env python3

import subprocess
import sys
import os
from pathlib import Path

# Step 1: Run the batch Ruby to Python converter
repo_root = Path("/workspace")
batch_converter = repo_root / "batch_ruby2py_converter.py"

print("🐍 STEP 1: Converting Ruby files to Python using batch converter")
print("="*70)

if not batch_converter.exists():
    print(f"❌ Batch converter not found: {batch_converter}")
    sys.exit(1)

try:
    # Run the batch converter
    result = subprocess.run(
        [sys.executable, str(batch_converter), "--repo-root", str(repo_root)],
        cwd=repo_root,
        text=True
    )
    
    print(f"Batch converter completed with exit code: {result.returncode}")
    
except Exception as e:
    print(f"❌ Error running batch converter: {e}")
    sys.exit(1)

print("✅ Step 1 completed - Ruby files converted to Python")