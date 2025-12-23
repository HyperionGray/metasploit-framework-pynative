#!/usr/bin/env python3

import os
import sys

# Ensure we're in the right directory
os.chdir('/workspace')
sys.path.insert(0, '/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Executing Ruby to Python conversion...")

# Execute the conversion
exec(open('batch_ruby_to_python_converter.py').read())