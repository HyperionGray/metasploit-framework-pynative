#!/usr/bin/env python3
import subprocess
import sys
import os

os.chdir('/workspace')

print("🚀 IMMEDIATE EXECUTION: ROUNDS 3 & 4")
print("=" * 50)

result = subprocess.run([sys.executable, 'immediate_execution.py'])
print(f"\nExecution completed with return code: {result.returncode}")