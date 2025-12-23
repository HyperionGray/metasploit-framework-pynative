#!/usr/bin/env python3
import os
import subprocess
import datetime
from pathlib import Path

def get_file_date(filepath):
    """Get the creation/modification date of a file from git history"""
    try:
        # Get git creation date (first commit)
        result = subprocess.run([
            'git', 'log', '--follow', '--format=%ai', '--reverse', str(filepath)
        ], capture_output=True, text=True, cwd="/workspace")
        
        if result.returncode == 0 and result.stdout.strip():
            git_dates = result.stdout.strip().split('\n')
            first_commit = git_dates[0]
            
            # Parse git date format: 2021-01-15 10:30:45 -0500
            date_part = first_commit.split()[0]
            return datetime.datetime.strptime(date_part, '%Y-%m-%d')
        
        # Fallback to filesystem modification time
        stat = Path(filepath).stat()
        return datetime.datetime.fromtimestamp(stat.st_mtime)
        
    except Exception as e:
        return None

def find_ruby_files(directory):
    ruby_files = []
    for root, dirs, files in os.walk(directory):
        # Skip certain directories
        if any(skip in root for skip in ['legacy', 'python_framework', '.git', 'spec', 'test']):
            continue
        for file in files:
            if file.endswith('.rb'):
                ruby_files.append(os.path.join(root, file))
    return ruby_files

if __name__ == "__main__":
    workspace = "/workspace"
    ruby_files = find_ruby_files(workspace)
    cutoff_date = datetime.datetime(2021, 1, 1)
    
    print(f"Found {len(ruby_files)} Ruby files:")
    
    pre_2020 = []
    post_2020 = []
    unknown = []
    
    for file in ruby_files:
        file_date = get_file_date(file)
        if file_date:
            if file_date >= cutoff_date:
                post_2020.append(file)
            else:
                pre_2020.append(file)
        else:
            unknown.append(file)
    
    print(f"\nClassification:")
    print(f"Pre-2020 files (to move to legacy): {len(pre_2020)}")
    print(f"Post-2020 files (to convert to Python): {len(post_2020)}")
    print(f"Unknown date files: {len(unknown)}")
    
    print(f"\nPost-2020 Ruby files to convert:")
    for i, file in enumerate(post_2020[:15]):  # Show first 15
        rel_path = os.path.relpath(file, workspace)
        file_date = get_file_date(file)
        date_str = file_date.strftime('%Y-%m-%d') if file_date else 'unknown'
        print(f"{i+1:2d}. {rel_path} ({date_str})")
    
    if len(post_2020) > 15:
        print(f"... and {len(post_2020) - 15} more post-2020 files")
    
    # Group by directory
    dirs = {}
    for file in post_2020:
        rel_path = os.path.relpath(file, workspace)
        dir_name = os.path.dirname(rel_path)
        if dir_name not in dirs:
            dirs[dir_name] = 0
        dirs[dir_name] += 1
    
    print(f"\nPost-2020 Ruby files by directory:")
    for dir_name, count in sorted(dirs.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{count:3d} files in {dir_name}")