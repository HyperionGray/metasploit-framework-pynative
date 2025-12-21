#!/usr/bin/env python3
"""
Quick Ruby File Counter and Classifier
Check current state before migration
"""

import os
import re
import datetime
from pathlib import Path

def count_ruby_files():
    workspace = Path('/workspace')
    
    print("🔍 RUBY FILE INVENTORY - PRE-MIGRATION")
    print("=" * 50)
    
    # Find all Ruby files
    ruby_files = []
    for rb_file in workspace.rglob("*.rb"):
        # Skip certain directories
        if not any(skip_dir in str(rb_file) for skip_dir in 
                  ['spec/', 'test/', '.git/', 'vendor/', 'legacy/', 'external/']):
            ruby_files.append(rb_file)
    
    print(f"Total Ruby files found: {len(ruby_files)}")
    
    # Classify by date
    post_2020 = []
    pre_2020 = []
    unknown = []
    
    for rb_file in ruby_files:
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
                        post_2020.append((rb_file, date_str))
                    else:
                        pre_2020.append((rb_file, date_str))
                    continue
                except ValueError:
                    pass
            
            unknown.append(rb_file)
                
        except Exception:
            unknown.append(rb_file)
    
    print(f"Post-2020 modules (conversion targets): {len(post_2020)}")
    print(f"Pre-2020 modules (legacy candidates): {len(pre_2020)}")
    print(f"Unknown classification: {len(unknown)}")
    
    # Show some examples
    if post_2020:
        print("\n📋 Sample Post-2020 Modules (Top 10):")
        for i, (rb_file, date) in enumerate(post_2020[:10]):
            rel_path = rb_file.relative_to(workspace)
            print(f"  {i+1}. {rel_path} ({date})")
    
    if pre_2020:
        print(f"\n📋 Sample Pre-2020 Modules (showing 5 of {len(pre_2020)}):")
        for i, (rb_file, date) in enumerate(pre_2020[:5]):
            rel_path = rb_file.relative_to(workspace)
            print(f"  {i+1}. {rel_path} ({date})")
    
    # Check for existing Python conversions
    python_files = []
    for py_file in workspace.rglob("modules/**/*.py"):
        if not any(skip_dir in str(py_file) for skip_dir in 
                  ['spec/', 'test/', '.git/', 'vendor/', 'legacy/', 'external/']):
            python_files.append(py_file)
    
    print(f"\n🐍 Existing Python modules: {len(python_files)}")
    
    return {
        'total_ruby': len(ruby_files),
        'post_2020': len(post_2020),
        'pre_2020': len(pre_2020),
        'unknown': len(unknown),
        'existing_python': len(python_files)
    }

if __name__ == '__main__':
    stats = count_ruby_files()
    
    print("\n" + "=" * 50)
    print("🎯 MIGRATION READINESS ASSESSMENT")
    print("=" * 50)
    
    if stats['post_2020'] > 0:
        print(f"✅ {stats['post_2020']} post-2020 modules ready for conversion")
    else:
        print("⚠️  No post-2020 modules found for conversion")
    
    if stats['pre_2020'] > 0:
        print(f"📦 {stats['pre_2020']} pre-2020 modules ready for legacy migration")
    else:
        print("ℹ️  No pre-2020 modules found")
    
    if stats['existing_python'] > 0:
        print(f"🐍 {stats['existing_python']} Python modules already exist")
    
    print("\n🚀 Ready to execute Round 2 Enhanced migration!")