#!/usr/bin/env python3

import os
import sys
import subprocess
from pathlib import Path

# Execute Round 2 directly
workspace = Path('/workspace')
os.chdir(workspace)

print("🐍🔥 ROUND 2: FIGHT! - DIRECT EXECUTION 🔥🐍")
print("=" * 50)

# Execute the round 2 script
try:
    result = subprocess.run([
        sys.executable, '/workspace/round2_execute.py'
    ], cwd='/workspace')
    
    print(f"\nRound 2 completed with return code: {result.returncode}")
    
except Exception as e:
    print(f"Error: {e}")

print("\n🎯 ROUND 2 EXECUTION FINISHED!")