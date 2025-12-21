#!/usr/bin/env python3

import os
import sys
import subprocess

def execute_conversion():
    """Execute the Ruby to Python conversion"""
    
    print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
    print("=" * 60)
    print("Alright gang only 7.1k ruby files to go!! let's rock this potato!!!!!")
    print("Remember only stuff after 2020:")
    print("- Is it ruby? Make it python.")
    print("only rule. GO.")
    print("=" * 60)
    
    # Change to workspace
    workspace_dir = "/workspace"
    os.chdir(workspace_dir)
    
    # Check if converter exists
    converter_path = os.path.join(workspace_dir, "batch_ruby_to_python_converter.py")
    if not os.path.exists(converter_path):
        print(f"❌ Converter script not found: {converter_path}")
        return False
    
    print(f"\n🔥 EXECUTING CONVERSION...")
    print(f"Workspace: {workspace_dir}")
    print(f"Converter: {converter_path}")
    print("-" * 40)
    
    try:
        # Execute the converter
        result = subprocess.run([
            sys.executable, converter_path
        ], cwd=workspace_dir)
        
        if result.returncode == 0:
            print("\n🎉 PYTHON WINS ROUND 1! 🐍")
            print("✅ All post-2020 Ruby files converted to Python!")
            print("🚀 Let's rock this potato indeed!")
            return True
        else:
            print(f"\n❌ Conversion failed with return code: {result.returncode}")
            return False
            
    except Exception as e:
        print(f"\n❌ Error during conversion: {e}")
        return False

if __name__ == '__main__':
    success = execute_conversion()
    sys.exit(0 if success else 1)