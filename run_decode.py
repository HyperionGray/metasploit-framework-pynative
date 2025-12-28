#!/usr/bin/env python3
import subprocess
import sys
import os

os.chdir('/workspace')
result = subprocess.run([sys.executable, 'decode_error.py'], capture_output=True, text=True)
print("STDOUT:")
print(result.stdout)
print("STDERR:")
print(result.stderr)
print("Return code:", result.returncode)