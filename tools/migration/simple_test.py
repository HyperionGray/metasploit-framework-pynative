#!/usr/bin/env python3

import re
from pathlib import Path
from datetime import datetime

# Simple test
file_path = Path("/workspace/modules/exploits/windows/http/manageengine_adaudit_plus_cve_2022_28219.rb")

if file_path.exists():
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Test our pattern
    pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
    match = pattern.search(content)
    
    if match:
        date_str = match.group(1)
        print(f"Found date: {date_str}")
        
        # Parse date
        try:
            disclosure_date = datetime.strptime(date_str, '%Y-%m-%d')
            cutoff_date = datetime(2021, 1, 1)
            
            if disclosure_date >= cutoff_date:
                print(f"✓ Post-2020 module: {disclosure_date}")
            else:
                print(f"✗ Pre-2021 module: {disclosure_date}")
        except Exception as e:
            print(f"Error parsing date: {e}")
    else:
        print("No disclosure date found")
else:
    print("File not found")

# Test on a few more files
test_files = [
    "/workspace/modules/exploits/windows/http/moveit_cve_2023_34362.rb",
    "/workspace/modules/exploits/windows/http/apache_chunked.rb"  # This should be older
]

for test_file in test_files:
    path = Path(test_file)
    if path.exists():
        with open(path, 'r') as f:
            content = f.read()
        match = pattern.search(content)
        if match:
            print(f"{path.name}: {match.group(1)}")
        else:
            print(f"{path.name}: No date found")
    else:
        print(f"{path.name}: File not found")