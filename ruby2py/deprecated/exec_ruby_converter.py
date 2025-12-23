#!/usr/bin/env python3

import os
import sys

# Setup
os.chdir('/workspace')
sys.path.insert(0, '/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Execute conversion
exec(open('/workspace/batch_ruby_to_python_converter.py').read())