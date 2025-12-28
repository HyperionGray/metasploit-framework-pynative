#!/usr/bin/env python3
"""
Test the constant extraction logic.
"""

import re

def test_extraction():
    """Test extracting constants from a small sample."""
    
    filepath = "/workspace/lib/rex/post/meterpreter/extensions/stdapi/railgun/def/windows/api_constants.rb"
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        # Read first 1000 lines to test
        lines = []
        for i, line in enumerate(f):
            if i >= 1000:
                break
            lines.append(line)
        content = ''.join(lines)
    
    # Find all add_const calls
    pattern = r"win_const_mgr\.add_const\('([^']+)',\s*(0x[0-9A-Fa-f]+)\)"
    matches = re.findall(pattern, content)
    
    print(f"Found {len(matches)} constants in first 1000 lines")
    
    # Show first 10 matches
    for i, (const_name, const_value) in enumerate(matches[:10]):
        print(f"  {const_name} = {const_value}")
    
    return len(matches) > 0

if __name__ == "__main__":
    success = test_extraction()
    print(f"Extraction test: {'PASSED' if success else 'FAILED'}")