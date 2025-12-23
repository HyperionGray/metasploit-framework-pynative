#!/usr/bin/env python3

import subprocess
import sys
import os

# Execute Round 2 migration
os.chdir('/workspace')

print("🐍🔥 EXECUTING ROUND 2: FIGHT! 🔥🐍")
print("=" * 40)

try:
    # Run the direct migration
    result = subprocess.run([
        sys.executable, '/workspace/round2_direct.py'
    ], cwd='/workspace')
    
    print(f"\nExecution completed with return code: {result.returncode}")
    
except Exception as e:
    print(f"Execution error: {e}")

print("\n🎯 ROUND 2 EXECUTION COMPLETE!")
print("🐍 PYTHON VICTORY! 🐍")