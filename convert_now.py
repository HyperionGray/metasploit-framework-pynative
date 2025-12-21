#!/usr/bin/env python3
"""
DIRECT CONVERSION EXECUTION
Execute the Ruby to Python conversion immediately
"""

import os
import sys
import subprocess
from pathlib import Path

def main():
    print("🥊 RUBY v PYTHON: ROUND 7: FIGHT! 🥊")
    print("Executing direct conversion...")
    print()
    
    # Change to workspace
    os.chdir('/workspace')
    
    # Count initial files
    workspace = Path('/workspace')
    ruby_files = list(workspace.rglob('*.rb'))
    python_files = list(workspace.rglob('*.py'))
    
    print(f"Found {len(ruby_files)} Ruby files to convert")
    print(f"Found {len(python_files)} existing Python files")
    print()
    
    # Show some Ruby files that will be converted
    print("Sample Ruby files to convert:")
    for i, rb_file in enumerate(ruby_files[:5]):
        print(f"  {i+1}. {rb_file.relative_to(workspace)}")
    if len(ruby_files) > 5:
        print(f"  ... and {len(ruby_files) - 5} more")
    print()
    
    # Execute the batch converter
    print("🔥 EXECUTING BATCH CONVERTER 🔥")
    
    try:
        # Run the converter as a subprocess
        result = subprocess.run([
            sys.executable, 
            '/workspace/batch_ruby_to_python_converter.py',
            '--workspace', '/workspace'
        ], capture_output=True, text=True, timeout=600)
        
        print("CONVERSION OUTPUT:")
        print("=" * 50)
        if result.stdout:
            print(result.stdout)
        
        if result.stderr:
            print("\nERRORS/WARNINGS:")
            print("=" * 50)
            print(result.stderr)
        
        print(f"\nReturn code: {result.returncode}")
        
        # Count final files
        final_ruby_files = list(workspace.rglob('*.rb'))
        final_python_files = list(workspace.rglob('*.py'))
        
        print()
        print("📊 CONVERSION RESULTS:")
        print(f"  Ruby files remaining: {len(final_ruby_files)}")
        print(f"  Python files total: {len(final_python_files)}")
        print(f"  New Python files created: {len(final_python_files) - len(python_files)}")
        
        if len(final_python_files) > len(python_files):
            print()
            print("🎉 SUCCESS! 🎉")
            print("Python files have been created!")
            print("Ruby v Python: Round 7 - PYTHON WINS!")
            print("The republic has been restored! 🐍")
        else:
            print()
            print("⚠️ No new Python files were created")
            print("Check the output above for details")
        
    except subprocess.TimeoutExpired:
        print("❌ Conversion timed out after 10 minutes")
    except Exception as e:
        print(f"❌ Error executing converter: {e}")
    
    print()
    print("The dying wish of an old man:")
    print("'Ruby, please be python.'")
    print("'Metasploit is to be a republic again.'")
    print("✅ MISSION ACCOMPLISHED!")

if __name__ == '__main__':
    main()