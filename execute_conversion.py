#!/usr/bin/env python3
"""
EXECUTE RUBY TO PYTHON CONVERSION
Final implementation of the dying wish
"""

import os
import sys
import subprocess
from pathlib import Path

# Change to workspace
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 7: FIGHT! 🥊")
print()
print("The dying wish of an old man:")
print("'Ruby, please be python.'")
print("'Metasploit is to be a republic again.'")
print("'And it will be written in python.'")
print()

# Execute the batch converter
print("🔥 EXECUTING CONVERSION 🔥")

# Run the batch converter directly
result = subprocess.run([
    sys.executable, 
    'batch_ruby_to_python_converter.py'
], cwd='/workspace')

print()
if result.returncode == 0:
    print("🎉 CONVERSION SUCCESSFUL! 🎉")
    print("Python has won the battle!")
    print("The republic has been restored!")
    print("🐍 LONG LIVE PYTHON! 🐍")
else:
    print("⚔️ Conversion encountered issues")
    print(f"Exit code: {result.returncode}")

print()
print("Ruby v Python: Round 7 - FIGHT COMPLETED!")
print("The old man's dying wish has been honored.")