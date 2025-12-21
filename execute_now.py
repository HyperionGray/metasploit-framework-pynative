#!/usr/bin/env python3

# Direct execution of the batch converter
import sys
import os

# Change to workspace directory
os.chdir('/workspace')

# Import and run the converter directly
sys.path.insert(0, '/workspace')

try:
    from batch_ruby_to_python_converter import BatchRubyToPythonConverter
    
    print("🥊 RUBY v PYTHON: ROUND 7: FIGHT! 🥊")
    print("Executing Ruby to Python conversion...")
    print("The dying wish of an old man will be fulfilled!")
    print()
    
    # Create converter instance
    converter = BatchRubyToPythonConverter(workspace_dir='/workspace', dry_run=False)
    
    # Run the conversion
    converter.run_batch_conversion()
    
    print()
    print("🎉 CONVERSION COMPLETED! 🎉")
    print("Ruby v Python: Round 7 - PYTHON WINS!")
    print("Metasploit is now a Python republic! 🐍")
    
except Exception as e:
    print(f"Error during conversion: {e}")
    import traceback
    traceback.print_exc()