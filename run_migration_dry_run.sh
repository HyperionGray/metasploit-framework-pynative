#!/usr/bin/env python3
# Run the migration script in dry-run mode to see what would be processed

import subprocess
import sys
import os

os.chdir('/workspace')
result = subprocess.run([sys.executable, 'migrate_ruby_to_python.py', '--dry-run', '--verbose'], 
                       capture_output=True, text=True)

print("STDOUT:")
print(result.stdout)
print("\nSTDERR:")
print(result.stderr)
print(f"\nReturn code: {result.returncode}")