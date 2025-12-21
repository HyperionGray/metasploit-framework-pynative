#!/usr/bin/env python3

# Execute the Ruby killer immediately
import subprocess
import sys
import os

os.chdir('/workspace')

print("🔥 EXECUTING RUBY KILLER 🔥")
print("Ruby v Python: Round 7: FIGHT!")
print()

# Run the Ruby killer
result = subprocess.run([sys.executable, 'ruby_killer_execute.py'])

print()
print(f"Ruby killer completed with exit code: {result.returncode}")

if result.returncode == 0:
    print("🎉 PYTHON WINS! The republic is restored! 🐍")
else:
    print("⚔️ Battle outcome unclear")

print()
print("The dying wish has been honored!")