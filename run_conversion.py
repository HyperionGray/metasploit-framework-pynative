#!/usr/bin/env python3
import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

# Execute the comprehensive conversion
print("🚀 Starting comprehensive Ruby to Python conversion...")
result = subprocess.run([sys.executable, "execute_comprehensive_conversion.py"], 
                       capture_output=False, text=True)

print(f"\nConversion process completed with exit code: {result.returncode}")
sys.exit(result.returncode)