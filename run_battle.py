#!/usr/bin/env python3

# Execute the final battle immediately
import subprocess
import sys
import os

os.chdir('/workspace')

print("Executing final battle...")
result = subprocess.run([sys.executable, '/workspace/final_battle.py'])

print(f"Battle completed with exit code: {result.returncode}")