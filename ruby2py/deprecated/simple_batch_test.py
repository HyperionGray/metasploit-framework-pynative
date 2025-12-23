#!/usr/bin/env python3
"""Simple test of batch conversion"""

import sys
import os
from pathlib import Path
from datetime import datetime
import re

# Add workspace to path
sys.path.insert(0, '/workspace')

def test_batch_conversion():
    """Test the batch conversion process"""
    
    workspace = Path('/workspace')
    exploits_dir = workspace / "modules" / "exploits" / "linux" / "http"
    
    print(f"Testing batch conversion in: {exploits_dir}")
    
    # Find Ruby files
    ruby_files = list(exploits_dir.glob("*.rb"))
    print(f"Found {len(ruby_files)} Ruby files")
    
    # Test on first few files
    for i, ruby_file in enumerate(ruby_files[:3]):
        print(f"\n{i+1}. Testing: {ruby_file.name}")
        
        # Check if it's post-2020
        try:
            with open(ruby_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Look for disclosure date
            pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
            match = pattern.search(content)
            
            if match:
                date_str = match.group(1)
                try:
                    disclosure_date = datetime.strptime(date_str, '%Y-%m-%d')
                    cutoff_date = datetime(2021, 1, 1)
                    
                    if disclosure_date >= cutoff_date:
                        print(f"  ✓ Post-2020: {disclosure_date.strftime('%Y-%m-%d')}")
                        
                        # Try to convert this file
                        python_file = ruby_file.with_suffix('.py')
                        if python_file.exists():
                            print(f"  → Python version already exists: {python_file.name}")
                        else:
                            print(f"  → Would convert to: {python_file.name}")
                            
                            # Show first few lines of Ruby file
                            lines = content.split('\n')
                            print("    Ruby content preview:")
                            for j, line in enumerate(lines[:5]):
                                print(f"      {j+1}: {line}")
                    else:
                        print(f"  ✗ Pre-2021: {disclosure_date.strftime('%Y-%m-%d')}")
                        
                except ValueError as e:
                    print(f"  ? Invalid date format: {date_str}")
            else:
                print("  ? No disclosure date found")
                
        except Exception as e:
            print(f"  ✗ Error reading file: {e}")

if __name__ == '__main__':
    test_batch_conversion()