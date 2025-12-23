#!/usr/bin/env python3
import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

# Run the count script
result = subprocess.run([sys.executable, 'count_ruby_files.py'], 
                       capture_output=True, text=True)

print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)
print(f"Return code: {result.returncode}")