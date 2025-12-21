#!/usr/bin/env python3

# Execute the conversion immediately
import subprocess
import sys
import os

os.chdir('/workspace')
print("Executing Ruby to Python conversion...")

# Run the converter
result = subprocess.run([sys.executable, '/workspace/convert_now.py'])
print(f"Conversion completed with exit code: {result.returncode}")

if result.returncode == 0:
    print("🎉 PYTHON WINS! The republic is restored! 🐍")
else:
    print("⚔️ Battle continues...")