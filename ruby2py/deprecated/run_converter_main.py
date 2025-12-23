#!/usr/bin/env python3

import os
import sys

# Setup environment
os.chdir('/workspace')
sys.path.insert(0, '/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Import and run the main function from the converter
try:
    import batch_ruby_to_python_converter
    batch_ruby_to_python_converter.main()
    print("🎉 PYTHON WINS! 🐍")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()