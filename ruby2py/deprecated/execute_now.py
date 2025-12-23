#!/usr/bin/env python3

import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

print("🐍🔥 ROUND 2: FIGHT! - EXECUTING NOW! 🔥🐍")
print("=" * 50)

# Execute the Round 2 fight
try:
    result = subprocess.run([sys.executable, 'round2_fight.py'], text=True)
    print(f"Round 2 execution completed with return code: {result.returncode}")
except Exception as e:
    print(f"Error executing Round 2: {e}")

print("\n🎯 MISSION STATUS: ROUND 2 EXECUTED!")
print("🐍 Check output above for results 🐍")