#!/usr/bin/env python3

import subprocess
import sys

# Run the quick assessment
print("Running quick assessment...")
result = subprocess.run([sys.executable, 'quick_assessment.py'], capture_output=True, text=True)

print("STDOUT:")
print(result.stdout)

if result.stderr:
    print("STDERR:")
    print(result.stderr)

print(f"Return code: {result.returncode}")