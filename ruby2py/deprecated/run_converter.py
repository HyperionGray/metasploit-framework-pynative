#!/usr/bin/env python3

import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

# Run the batch converter
try:
    result = subprocess.run([sys.executable, 'batch_plugin_converter.py'], 
                          capture_output=True, text=True, timeout=60)
    print("STDOUT:")
    print(result.stdout)
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    print(f"Return code: {result.returncode}")
except subprocess.TimeoutExpired:
    print("Conversion timed out")
except Exception as e:
    print(f"Error running converter: {e}")