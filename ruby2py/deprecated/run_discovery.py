#!/usr/bin/env python3
import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

# Run the Ruby file discovery
print("=== Discovering Ruby files that need conversion ===")
result = subprocess.run([sys.executable, "find_ruby_files.py"], capture_output=True, text=True)
print(result.stdout)
if result.stderr:
    print("STDERR:", result.stderr)