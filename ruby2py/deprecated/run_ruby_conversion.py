#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Change to workspace
workspace = Path("/workspace")
os.chdir(workspace)

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Add workspace to path and import converter
sys.path.insert(0, str(workspace))

try:
    # Import the converter module
    import batch_ruby_to_python_converter as converter_module
    
    # Create converter instance
    converter = converter_module.BatchRubyToPythonConverter(
        workspace_dir=str(workspace),
        dry_run=False
    )
    
    # Run the conversion
    print("Starting batch conversion...")
    converter.run_batch_conversion()
    
    print("🎉 PYTHON WINS! 🐍")
    
except ImportError as e:
    print(f"Import error: {e}")
    # Try to run as subprocess instead
    import subprocess
    result = subprocess.run([sys.executable, "batch_ruby_to_python_converter.py"])
    if result.returncode == 0:
        print("🎉 PYTHON WINS! 🐍")
    else:
        print(f"❌ Failed: {result.returncode}")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()