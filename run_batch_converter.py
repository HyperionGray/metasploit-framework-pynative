#!/usr/bin/env python3

import os
import sys

# Change to workspace
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Execute the batch converter as a module
if __name__ == '__main__':
    # Import the converter
    sys.path.insert(0, '/workspace')
    
    try:
        import batch_ruby_to_python_converter
        
        # Create and run converter
        converter = batch_ruby_to_python_converter.BatchRubyToPythonConverter(
            workspace_dir="/workspace",
            dry_run=False
        )
        
        converter.run_batch_conversion()
        
        print("🎉 PYTHON WINS! 🐍")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()