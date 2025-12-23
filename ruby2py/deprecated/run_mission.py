#!/usr/bin/env python3
import subprocess
import sys
import os

# Change to workspace
os.chdir('/workspace')

# Execute the mission
print("🚀 EXECUTING FINAL MISSION...")
result = subprocess.run([sys.executable, 'execute_mission.py'], 
                       capture_output=True, text=True)

print(result.stdout)
if result.stderr:
    print("STDERR:")
    print(result.stderr)

print(f"\nReturn code: {result.returncode}")
if result.returncode == 0:
    print("🎉 MISSION SUCCESS!")
else:
    print("❌ Mission failed")