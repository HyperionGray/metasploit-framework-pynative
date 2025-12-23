#!/usr/bin/env python3
import subprocess
import sys
import os

# Execute the direct conversion
os.chdir('/workspace')
print("🚀 Executing Ruby to Python conversion...")

# Run the direct conversion script
result = subprocess.run([sys.executable, "direct_conversion_exec.py"])
print(f"\nDirect conversion completed with exit code: {result.returncode}")

# Also run the comprehensive version as backup
print("\n🔄 Running comprehensive conversion as backup...")
result2 = subprocess.run([sys.executable, "execute_comprehensive_conversion.py"])
print(f"Comprehensive conversion completed with exit code: {result2.returncode}")

print("\n🎉 All conversion processes completed!")