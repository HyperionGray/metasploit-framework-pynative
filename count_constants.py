#!/usr/bin/env python3
"""
Count constants in the original file.
"""

import re

def count_constants():
    filepath = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    
    count = 0
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'win_const_mgr.add_const(' in line:
                count += 1
    
    print(f"Total constants found: {count}")
    return count

if __name__ == "__main__":
    count_constants()