#!/usr/bin/env python3

import os
import subprocess
import sys

# Simple execution of Round 2
os.chdir('/workspace')

print("🐍🔥 ROUND 2: FIGHT! - EXECUTING NOW 🔥🐍")

# Run the migration script
try:
    result = subprocess.run([
        sys.executable, 
        '/workspace/round2_fight_execute.py'
    ], cwd='/workspace', capture_output=False)
    
    print(f"\nMigration completed with return code: {result.returncode}")
    
except Exception as e:
    print(f"Error: {e}")

print("🎯 EXECUTION COMPLETE!")