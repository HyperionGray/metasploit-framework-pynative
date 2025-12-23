#!/usr/bin/env python3

import subprocess
import sys
import os

def main():
    print("🐍 EXECUTING RUBY TO PYTHON CONVERSION 🐍")
    print("The fever can only be cured with MORE PYTHON!")
    
    os.chdir("/workspace")
    
    # Run the ultimate conversion
    try:
        result = subprocess.run([sys.executable, "ultimate_ruby_killer.py"], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
    except Exception as e:
        print(f"Error: {e}")
    
    # Also run the immediate conversion
    try:
        result = subprocess.run([sys.executable, "immediate_ruby_to_python.py"], 
                              capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()