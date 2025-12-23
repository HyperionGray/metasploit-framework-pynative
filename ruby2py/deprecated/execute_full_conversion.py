#!/usr/bin/env python3
import subprocess
import sys
import os

os.chdir('/workspace')

print("🔍 Quick Ruby file scan...")
result = subprocess.run([sys.executable, "quick_ruby_scan.py"])

print("\n" + "="*60)
print("🚀 Now executing comprehensive conversion...")
print("="*60)

result = subprocess.run([sys.executable, "execute_comprehensive_conversion.py"])
print(f"\nConversion completed with exit code: {result.returncode}")