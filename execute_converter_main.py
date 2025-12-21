#!/usr/bin/env python3

import os
import sys

# Change to workspace
os.chdir('/workspace')

print("🥊 RUBY v PYTHON: ROUND 1: FIGHT! 🥊")
print("Converting post-2020 Ruby files to Python...")

# Execute the converter by running it as main
if __name__ == '__main__':
    # Simulate command line execution
    sys.argv = ['batch_ruby_to_python_converter.py']
    
    # Execute the converter
    with open('/workspace/batch_ruby_to_python_converter.py') as f:
        code = compile(f.read(), 'batch_ruby_to_python_converter.py', 'exec')
        exec(code)
    
    print("🎉 PYTHON WINS! 🐍")