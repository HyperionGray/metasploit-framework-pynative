#!/usr/bin/env python3

import os
import sys
from pathlib import Path

# Set up environment
workspace = Path("/workspace")
os.chdir(workspace)
sys.path.insert(0, str(workspace))

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("=" * 60)
print("Converting all post-2020 Ruby files to Python...")
print("=" * 60)

# Import and run the converter
try:
    from batch_ruby_to_python_converter import BatchRubyToPythonConverter
    
    # Create converter with no dry run
    converter = BatchRubyToPythonConverter(
        workspace_dir=str(workspace),
        dry_run=False
    )
    
    # Execute the conversion
    converter.run_batch_conversion()
    
    print("\n🎉 PYTHON WINS ROUND 1! 🐍")
    print("Ruby files converted to Python successfully!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)