#!/usr/bin/env python3
import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

# Run the assessment script
result = subprocess.run([sys.executable, 'assess_round3.py'], 
                       capture_output=True, text=True)

print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)