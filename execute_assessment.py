#!/usr/bin/env python3
import subprocess
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

print("🔍 ASSESSING ROUND 3 STATUS...")
print("=" * 60)

# Run the assessment script
result = subprocess.run([sys.executable, 'assess_round3.py'], 
                       capture_output=True, text=True)

print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)

print("\n" + "=" * 60)
print("🎯 NEXT STEPS BASED ON ASSESSMENT:")
print("If Round 3 is incomplete, we'll complete it first")
print("If Round 3 is complete, we'll proceed to Round 4: KILL RUBY!")