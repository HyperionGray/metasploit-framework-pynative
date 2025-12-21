#!/usr/bin/env python3

# Execute the conversion directly
import sys
import os
sys.path.insert(0, '/workspace')

# Change to workspace
os.chdir('/workspace')

# Import and run the conversion
from direct_ruby_conversion import convert_ruby_files

if __name__ == '__main__':
    convert_ruby_files()