#!/usr/bin/env python3

import os
import sys
import subprocess

# Change to workspace
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Run the converter as a subprocess
try:
    result = subprocess.run([sys.executable, 'batch_ruby_to_python_converter.py'], 
                          capture_output=False, text=True)
    
    if result.returncode == 0:
        print("🎉 PYTHON WINS! 🐍")
    else:
        print(f"❌ Conversion failed: {result.returncode}")
        
except Exception as e:
    print(f"Error: {e}")