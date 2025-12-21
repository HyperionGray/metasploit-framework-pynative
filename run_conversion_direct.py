#!/usr/bin/env python3

import os
import sys

# Change to workspace and run the conversion
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Import and run the converter directly
sys.path.insert(0, '/workspace')

try:
    from batch_ruby_to_python_converter import BatchRubyToPythonConverter
    
    converter = BatchRubyToPythonConverter(workspace_dir="/workspace", dry_run=False)
    converter.run_batch_conversion()
    
    print("🎉 PYTHON WINS ROUND 1! 🐍")
    
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)