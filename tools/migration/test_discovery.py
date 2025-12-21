#!/usr/bin/env python3
"""
Test discovery script for Ruby to Python migration
"""

import os
import re
from pathlib import Path
from datetime import datetime

def discover_post_2020_modules():
    """Discover modules with disclosure dates after 2020"""
    
    workspace = Path("/workspace")
    modules_dir = workspace / "modules" / "exploits"
    
    if not modules_dir.exists():
        print("Modules directory not found")
        return
    
    post_2020_modules = []
    cutoff_date = datetime(2021, 1, 1)
    
    # Pattern to match disclosure dates
    date_pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
    
    print("Scanning for post-2020 exploit modules...")
    
    for ruby_file in modules_dir.rglob("*.rb"):
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            match = date_pattern.search(content)
            if match:
                date_str = match.group(1)
                try:
                    disclosure_date = datetime.strptime(date_str, '%Y-%m-%d')
                    if disclosure_date >= cutoff_date:
                        post_2020_modules.append({
                            'file': ruby_file.relative_to(workspace),
                            'date': date_str,
                            'parsed_date': disclosure_date
                        })
                except ValueError:
                    pass
                    
        except Exception as e:
            print(f"Error processing {ruby_file}: {e}")
    
    # Sort by date
    post_2020_modules.sort(key=lambda x: x['parsed_date'])
    
    print(f"\nFound {len(post_2020_modules)} post-2020 modules:")
    for module in post_2020_modules:
        print(f"  {module['date']}: {module['file']}")
    
    return post_2020_modules

if __name__ == '__main__':
    discover_post_2020_modules()