#!/usr/bin/env python3
"""
Direct execution of Ruby to Python conversion
"""

import os
import sys
import subprocess
from pathlib import Path

# Change to workspace
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 7: FIGHT! 🥊")
print("Executing batch conversion...")

# Run the batch converter directly
try:
    result = subprocess.run([
        sys.executable, 'batch_ruby_to_python_converter.py'
    ], check=False, text=True)
    
    print(f"Conversion completed with return code: {result.returncode}")
    
except Exception as e:
    print(f"Error: {e}")

print("🎉 PYTHON WINS! The republic is restored! 🐍")