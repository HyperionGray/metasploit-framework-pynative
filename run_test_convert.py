#!/usr/bin/env python3
"""Execute the test conversion"""

import subprocess
import sys
import os

os.chdir('/workspace')
result = subprocess.run([sys.executable, 'test_convert.py'], 
                       capture_output=True, text=True)

print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("\nSTDERR:")
    print(result.stderr)
print(f"\nReturn code: {result.returncode}")

# Also show the generated file if it exists
output_file = '/workspace/test_apache_airflow_dag_rce.py'
if os.path.exists(output_file):
    print(f"\n{'='*60}")
    print("GENERATED PYTHON FILE CONTENT:")
    print('='*60)
    with open(output_file, 'r') as f:
        content = f.read()
        lines = content.split('\n')
        for i, line in enumerate(lines[:100], 1):  # Show first 100 lines
            print(f"{i:3d}: {line}")
        if len(lines) > 100:
            print(f"... and {len(lines) - 100} more lines")