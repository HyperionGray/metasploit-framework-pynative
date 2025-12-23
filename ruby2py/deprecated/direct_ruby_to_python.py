#!/usr/bin/env python3

import os
import sys

# Change to workspace directory
os.chdir('/workspace')

# Add workspace to Python path
sys.path.insert(0, '/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("=" * 60)
print("Converting all post-2020 Ruby files to Python...")
print("=" * 60)

# Import and execute the converter
try:
    from batch_ruby_to_python_converter import BatchRubyToPythonConverter
    
    # Create converter instance
    converter = BatchRubyToPythonConverter(
        workspace_dir="/workspace",
        dry_run=False
    )
    
    # Run the conversion
    converter.run_batch_conversion()
    
    print("\n🎉 PYTHON WINS ROUND 1! 🐍")
    print("✅ Ruby to Python conversion completed!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Conversion error: {e}")
    sys.exit(1)