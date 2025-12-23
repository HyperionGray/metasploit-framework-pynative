#!/usr/bin/env python3

import subprocess
import sys
import os
from pathlib import Path

# Change to workspace directory
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("=" * 50)
print("Converting all post-2020 Ruby files to Python...")
print("=" * 50)

# Execute the batch converter
try:
    result = subprocess.run([
        sys.executable, 'batch_ruby_to_python_converter.py'
    ], check=False)
    
    if result.returncode == 0:
        print("\n🎉 PYTHON WINS! 🐍")
        print("All post-2020 Ruby files converted successfully!")
    else:
        print(f"\n❌ Conversion failed with return code: {result.returncode}")
        
except Exception as e:
    print(f"❌ Error running conversion: {e}")