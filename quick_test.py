#!/usr/bin/env python3

import re
from pathlib import Path

# Quick test of our regex patterns
file_path = Path("/workspace/modules/exploits/windows/http/manageengine_adaudit_plus_cve_2022_28219.rb")

if file_path.exists():
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Test patterns
    disclosure_date_pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
    name_pattern = re.compile(r"'Name'\s*=>\s*'([^']+)'")
    
    date_match = disclosure_date_pattern.search(content)
    name_match = name_pattern.search(content)
    
    print("Testing regex patterns:")
    print(f"Date match: {date_match.group(1) if date_match else 'None'}")
    print(f"Name match: {name_match.group(1) if name_match else 'None'}")
    
    # Show first few lines with DisclosureDate
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if 'DisclosureDate' in line:
            print(f"Line {i+1}: {line.strip()}")
            break
else:
    print("File not found")