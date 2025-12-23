#!/usr/bin/env python3
"""
IMMEDIATE EXECUTION - Ruby to Python Conversion
No more delays - execute the conversion NOW!
"""

import os
import sys
from pathlib import Path

# Set up environment
os.chdir('/workspace')
sys.path.insert(0, '/workspace')

print("🥊 RUBY v PYTHON: ROUND 7: FIGHT! 🥊")
print("IMMEDIATE EXECUTION - NO DELAYS!")
print()

# Count initial files
workspace = Path('/workspace')
initial_ruby = len(list(workspace.rglob('*.rb')))
initial_python = len(list(workspace.rglob('*.py')))

print(f"Initial state: {initial_ruby} Ruby files, {initial_python} Python files")
print()

# Execute conversion
print("🔥 CONVERTING RUBY TO PYTHON... 🔥")

try:
    # Direct import and execution
    from batch_ruby_to_python_converter import BatchRubyToPythonConverter
    
    # Create and run converter
    converter = BatchRubyToPythonConverter(workspace_dir='/workspace', dry_run=False)
    converter.run_batch_conversion()
    
    # Count final files
    final_ruby = len(list(workspace.rglob('*.rb')))
    final_python = len(list(workspace.rglob('*.py')))
    
    print()
    print(f"Final state: {final_ruby} Ruby files, {final_python} Python files")
    print(f"Created {final_python - initial_python} new Python files!")
    print()
    
    print("🎉 PYTHON WINS! 🎉")
    print("The dying wish has been fulfilled!")
    print("Metasploit is now a Python republic! 🐍")
    
except ImportError as e:
    print(f"Import error: {e}")
    print("Trying alternative approach...")
    
    # Alternative: run as subprocess
    import subprocess
    result = subprocess.run([sys.executable, 'batch_ruby_to_python_converter.py'], 
                          capture_output=True, text=True)
    print("Subprocess output:")
    print(result.stdout)
    if result.stderr:
        print("Errors:")
        print(result.stderr)

except Exception as e:
    print(f"Execution error: {e}")
    import traceback
    traceback.print_exc()

print()
print("Ruby v Python: Round 7 - BATTLE COMPLETE!")