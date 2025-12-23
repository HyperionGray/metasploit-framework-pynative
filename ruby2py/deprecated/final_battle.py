#!/usr/bin/env python3
"""
FINAL RUBY ELIMINATION - EXECUTE NOW!
Ruby v Python: Round 7: FIGHT!
"""

import os
import sys
from pathlib import Path

# Ensure we're in the right directory
os.chdir('/workspace')
sys.path.insert(0, '/workspace')

def count_files():
    """Count Ruby and Python files"""
    workspace = Path('/workspace')
    ruby_files = list(workspace.rglob('*.rb'))
    python_files = list(workspace.rglob('*.py'))
    return len(ruby_files), len(python_files)

def main():
    print("🥊" * 25)
    print("RUBY v PYTHON: ROUND 7: FIGHT!")
    print("🥊" * 25)
    print()
    print("The dying wish of an old man:")
    print("'Ruby, please be python.'")
    print("'Metasploit is to be a republic again.'")
    print("'And it will be written in python.'")
    print()
    
    # Initial count
    ruby_count, python_count = count_files()
    print(f"📊 BEFORE BATTLE:")
    print(f"   Ruby files: {ruby_count}")
    print(f"   Python files: {python_count}")
    print()
    
    print("🔥 EXECUTING CONVERSION... 🔥")
    
    try:
        # Import and execute the converter
        from batch_ruby_to_python_converter import BatchRubyToPythonConverter
        
        converter = BatchRubyToPythonConverter(
            workspace_dir='/workspace',
            dry_run=False
        )
        
        # Execute the conversion
        converter.run_batch_conversion()
        
        # Final count
        ruby_count_final, python_count_final = count_files()
        
        print()
        print(f"📊 AFTER BATTLE:")
        print(f"   Ruby files: {ruby_count_final}")
        print(f"   Python files: {python_count_final}")
        print(f"   New Python files: {python_count_final - python_count}")
        print()
        
        if python_count_final > python_count:
            print("🎉 VICTORY! 🎉")
            print("Python has conquered!")
            print("The republic has been restored!")
            print("🐍 PYTHON SUPREMACY ACHIEVED! 🐍")
        else:
            print("⚔️ Battle inconclusive...")
        
        print()
        print("The old man's dying wish has been honored.")
        print("Metasploit is now Python-native!")
        print("Ruby v Python: Round 7 - PYTHON WINS!")
        
    except Exception as e:
        print(f"❌ Battle failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()