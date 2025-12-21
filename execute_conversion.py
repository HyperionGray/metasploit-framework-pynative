#!/usr/bin/env python3

import subprocess
import sys
import os

# Execute the Ruby to Python conversion
print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting all post-2020 Ruby files to Python...")

os.chdir('/workspace')

# Run the batch converter
result = subprocess.run([sys.executable, 'batch_ruby_to_python_converter.py'])

if result.returncode == 0:
    print("🎉 PYTHON WINS! 🐍")
else:
    print(f"❌ Conversion failed: {result.returncode}")

sys.exit(result.returncode)