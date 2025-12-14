#!/usr/bin/env python3

import sys
import os
from pathlib import Path
sys.path.append('/workspace/tools/dev')

from discover_post_2020_exploits import ExploitDiscovery

# Test with a few known files
discovery = ExploitDiscovery()

# Test files we know exist
test_files = [
    "/workspace/modules/exploits/windows/http/manageengine_adaudit_plus_cve_2022_28219.rb",
    "/workspace/modules/exploits/windows/http/moveit_cve_2023_34362.rb"
]

print("Testing discovery on known files:")
for file_path in test_files:
    if Path(file_path).exists():
        result = discovery.parse_ruby_file(Path(file_path))
        if result:
            print(f"\n✓ {file_path}")
            print(f"  Name: {result['name']}")
            print(f"  Date: {result['disclosure_date']}")
            print(f"  CVEs: {result['cves']}")
            print(f"  Rank: {result['rank']}")
        else:
            print(f"\n✗ Failed to parse {file_path}")
    else:
        print(f"\n✗ File not found: {file_path}")

print("\nTesting directory scan on small subset...")
# Test on a small directory first
http_dir = Path("/workspace/modules/exploits/windows/http")
if http_dir.exists():
    # Just scan first 10 files to test
    ruby_files = list(http_dir.glob("*.rb"))[:10]
    print(f"Testing on {len(ruby_files)} files from {http_dir}")
    
    for ruby_file in ruby_files:
        result = discovery.parse_ruby_file(ruby_file)
        if result:
            print(f"  ✓ {ruby_file.name} - {result['disclosure_date']}")
        else:
            print(f"  - {ruby_file.name} - (no date or pre-2021)")