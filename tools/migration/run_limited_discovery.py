#!/usr/bin/env python3
"""
Limited discovery script for testing migration patterns
"""

import re
from pathlib import Path
from datetime import datetime

def limited_discovery():
    """Run limited discovery on a small set of files"""
    
    workspace = Path("/workspace")
    
    # Test files to check
    test_files = [
        "modules/exploits/windows/http/manageengine_adaudit_plus_cve_2022_28219.rb",
        "modules/exploits/linux/http/apache_airflow_dag_rce.rb",
        "modules/exploits/windows/http/moveit_cve_2023_34362.rb"
    ]
    
    date_pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
    cutoff_date = datetime(2021, 1, 1)
    
    print("Limited Ruby file discovery:")
    print("-" * 40)
    
    for test_file in test_files:
        file_path = workspace / test_file
        
        if file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                match = date_pattern.search(content)
                if match:
                    date_str = match.group(1)
                    try:
                        disclosure_date = datetime.strptime(date_str, '%Y-%m-%d')
                        classification = "POST-2020" if disclosure_date >= cutoff_date else "PRE-2020"
                        print(f"✓ {file_path.name}")
                        print(f"  Date: {date_str} ({classification})")
                    except ValueError:
                        print(f"? {file_path.name}")
                        print(f"  Invalid date: {date_str}")
                else:
                    print(f"? {file_path.name}")
                    print(f"  No disclosure date found")
                    
            except Exception as e:
                print(f"✗ {file_path.name}")
                print(f"  Error: {e}")
        else:
            print(f"✗ {file_path.name}")
            print(f"  File not found")
        
        print()

if __name__ == '__main__':
    limited_discovery()