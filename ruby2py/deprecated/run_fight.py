#!/usr/bin/env python3

import subprocess
import sys
import os

print("🐍🔥 ROUND 2: FIGHT! - FINAL EXECUTION 🔥🐍")
print("=" * 50)

os.chdir('/workspace')

# Execute the migration
subprocess.run([sys.executable, '/workspace/round2_fight_execute.py'])

print("\n🎯 ROUND 2 EXECUTION COMPLETE!")
print("🐍 PYTHON SUPREMACY! 🐍")