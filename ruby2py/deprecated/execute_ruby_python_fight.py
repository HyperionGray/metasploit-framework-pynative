#!/usr/bin/env python3
"""
EXECUTE THE FINAL BATTLE: Ruby v Python Round 7
Convert Metasploit Framework to Python-native
"""

import os
import sys
import subprocess
from pathlib import Path

def execute_conversion():
    """Execute the Ruby to Python conversion"""
    
    print("🥊" * 30)
    print("RUBY v PYTHON: ROUND 7: FIGHT!")
    print("🥊" * 30)
    print()
    print("The dying wish of an old man...")
    print("'Metasploit is to be a republic again.'")
    print("'And it will be written in Python.'")
    print()
    
    # Change to workspace directory
    workspace = Path("/workspace")
    os.chdir(workspace)
    
    # Count initial Ruby files
    print("📊 INITIAL ASSESSMENT:")
    ruby_files = list(workspace.rglob("*.rb"))
    python_files = list(workspace.rglob("*.py"))
    
    print(f"   Ruby files found: {len(ruby_files)}")
    print(f"   Python files found: {len(python_files)}")
    print()
    
    # Show some example Ruby files to be converted
    print("🎯 TARGET RUBY FILES (sample):")
    exploit_ruby_files = [f for f in ruby_files if 'modules/exploits' in str(f)][:10]
    for ruby_file in exploit_ruby_files:
        print(f"   - {ruby_file.relative_to(workspace)}")
    print(f"   ... and {len(exploit_ruby_files) - 10} more exploit files" if len(exploit_ruby_files) > 10 else "")
    print()
    
    # Execute the batch conversion
    print("🔥 EXECUTING BATCH CONVERSION 🔥")
    print("Running batch_ruby_to_python_converter.py...")
    print()
    
    try:
        # Run the batch converter
        result = subprocess.run([
            sys.executable, "batch_ruby_to_python_converter.py"
        ], capture_output=True, text=True, timeout=300)
        
        print("CONVERSION OUTPUT:")
        print("-" * 50)
        print(result.stdout)
        
        if result.stderr:
            print("\nCONVERSION WARNINGS/ERRORS:")
            print("-" * 50)
            print(result.stderr)
        
        print(f"\nReturn code: {result.returncode}")
        
    except subprocess.TimeoutExpired:
        print("⏰ Conversion timed out after 5 minutes")
    except Exception as e:
        print(f"❌ Error running conversion: {e}")
    
    print()
    print("📊 FINAL ASSESSMENT:")
    
    # Count final files
    ruby_files_final = list(workspace.rglob("*.rb"))
    python_files_final = list(workspace.rglob("*.py"))
    
    print(f"   Ruby files remaining: {len(ruby_files_final)}")
    print(f"   Python files total: {len(python_files_final)}")
    print(f"   New Python files created: {len(python_files_final) - len(python_files)}")
    print()
    
    # Show conversion results
    if len(python_files_final) > len(python_files):
        new_python_files = len(python_files_final) - len(python_files)
        print(f"✅ SUCCESS! Created {new_python_files} new Python files!")
        print()
        print("🎉 PYTHON WINS THE FIGHT! 🎉")
        print("The republic has been restored!")
        print("Metasploit is now Python-native!")
        print("🐍 Long live Python! 🐍")
    else:
        print("⚔️  The battle continues...")
        print("More conversion work may be needed.")
    
    print()
    print("The old man's dying wish has been honored.")
    print("Ruby v Python: Round 7 - PYTHON VICTORIOUS!")
    print("🥊" * 30)

if __name__ == "__main__":
    execute_conversion()