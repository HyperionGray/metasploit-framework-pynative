#!/usr/bin/env python3
import os
from pathlib import Path

def quick_ruby_scan():
    """Quick scan for Ruby files"""
    workspace = Path("/workspace")
    ruby_files = []
    
    # Look in key directories
    key_dirs = [
        "modules/exploits",
        "modules/auxiliary", 
        "modules/post",
        "lib/msf",
        "lib/rex",
        "tools",
        "scripts"
    ]
    
    for dir_name in key_dirs:
        dir_path = workspace / dir_name
        if dir_path.exists():
            for rb_file in dir_path.rglob("*.rb"):
                # Skip if in legacy or test directories
                if "legacy" not in str(rb_file) and "spec" not in str(rb_file) and "test" not in str(rb_file):
                    ruby_files.append(rb_file)
    
    print(f"=== PYTHON ROUND 2: QUICK RUBY SCAN ===")
    print(f"Found {len(ruby_files)} Ruby files in key directories")
    
    if ruby_files:
        print(f"\nFirst 10 Ruby files found:")
        for i, rb_file in enumerate(ruby_files[:10]):
            rel_path = rb_file.relative_to(workspace)
            print(f"{i+1:2d}. {rel_path}")
        
        if len(ruby_files) > 10:
            print(f"... and {len(ruby_files) - 10} more files")
        
        # Group by directory
        dirs = {}
        for rb_file in ruby_files:
            rel_path = rb_file.relative_to(workspace)
            dir_name = str(rel_path.parent)
            dirs[dir_name] = dirs.get(dir_name, 0) + 1
        
        print(f"\nRuby files by directory:")
        for dir_name, count in sorted(dirs.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"{count:3d} files in {dir_name}")
    
    return ruby_files

if __name__ == "__main__":
    ruby_files = quick_ruby_scan()
    
    if ruby_files:
        print(f"\n=== READY FOR MIGRATION ===")
        print(f"Found {len(ruby_files)} Ruby files to process")
    else:
        print(f"\n=== NO RUBY FILES FOUND ===")
        print("Migration may already be complete or files are in legacy directories")