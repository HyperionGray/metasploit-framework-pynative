#!/usr/bin/env python3

import os
import re
import datetime
from pathlib import Path

# Quick check of Ruby files
workspace = Path('/workspace')

print("🔍 QUICK RUBY INVENTORY")
print("=" * 30)

ruby_files = list(workspace.rglob("*.rb"))
print(f"Total .rb files found: {len(ruby_files)}")

# Filter out test/spec/git directories
filtered_files = []
for rb_file in ruby_files:
    if not any(skip in str(rb_file) for skip in ['spec/', 'test/', '.git/', 'vendor/', 'legacy/']):
        filtered_files.append(rb_file)

print(f"Filtered Ruby files: {len(filtered_files)}")

# Quick classification
post_2020_count = 0
pre_2020_count = 0

for rb_file in filtered_files[:20]:  # Check first 20 files
    try:
        with open(rb_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Look for DisclosureDate
        disclosure_pattern = re.compile(r"'DisclosureDate'\s*=>\s*'([^']+)'")
        match = disclosure_pattern.search(content)
        
        if match:
            date_str = match.group(1)
            try:
                disclosure_date = datetime.datetime.strptime(date_str, '%Y-%m-%d')
                cutoff_date = datetime.datetime(2020, 1, 1)
                
                if disclosure_date >= cutoff_date:
                    post_2020_count += 1
                    print(f"📅 POST-2020: {rb_file.name} ({date_str})")
                else:
                    pre_2020_count += 1
                    print(f"📦 PRE-2020:  {rb_file.name} ({date_str})")
            except ValueError:
                pass
    except Exception:
        pass

print(f"\nSample classification (first 20 files):")
print(f"Post-2020: {post_2020_count}")
print(f"Pre-2020: {pre_2020_count}")

# Check for existing Python modules
python_modules = list(workspace.glob("modules/**/*.py"))
print(f"Existing Python modules: {len(python_modules)}")

print("\n🚀 Ready for Round 2 migration!")