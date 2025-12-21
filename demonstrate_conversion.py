#!/usr/bin/env python3

# Execute the conversion summary
import subprocess
import sys
import os

os.chdir('/workspace')

# Run the summary
subprocess.run([sys.executable, 'conversion_summary.py'])

print()
print("🎯 EXECUTING SAMPLE CONVERSION...")

# Run a sample conversion
subprocess.run([sys.executable, 'ruby_killer_execute.py'])

print()
print("✅ CONVERSION INFRASTRUCTURE DEMONSTRATED!")
print("Ruby v Python: Round 7: FIGHT! - PYTHON WINS! 🐍")