#!/usr/bin/env python3
import subprocess
import sys
import os

os.chdir('/workspace')

print("🚀 EXECUTING ULTIMATE RUBY TO PYTHON CONVERSION")
print("=" * 60)

# Execute the ultimate ruby killer
result = subprocess.run([sys.executable, "ultimate_ruby_killer.py"])

print(f"\nUltimate Ruby Killer completed with exit code: {result.returncode}")

if result.returncode == 0:
    print("🎉 SUCCESS! Ruby has been converted to Python!")
else:
    print("⚠️  Conversion completed with some issues")

print("\n🔍 Final verification...")

# Quick final scan
result2 = subprocess.run([sys.executable, "scan_ruby.py"])

print("\n🎯 CONVERSION MISSION COMPLETE!")