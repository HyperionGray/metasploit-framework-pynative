#!/usr/bin/env python3
"""
Find all Ruby files in the repository and analyze their dates
"""
import os
import subprocess
import datetime
from pathlib import Path

def find_ruby_files(root_dir):
    """Find all .rb files in the repository"""
    ruby_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.rb'):
                ruby_files.append(os.path.join(root, file))
    return ruby_files

def get_file_dates(filepath):
    """Get creation and modification dates from git and filesystem"""
    try:
        # Get git creation date (first commit)
        result = subprocess.run([
            'git', 'log', '--follow', '--format=%ai', '--reverse', filepath
        ], capture_output=True, text=True, cwd='/workspace')
        
        git_dates = []
        if result.returncode == 0 and result.stdout.strip():
            git_dates = result.stdout.strip().split('\n')
        
        # Get filesystem dates
        stat = os.stat(filepath)
        mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        
        return {
            'git_first': git_dates[0] if git_dates else None,
            'git_last': git_dates[-1] if git_dates else None,
            'fs_mtime': mtime.isoformat()
        }
    except Exception as e:
        return {'error': str(e)}

def main():
    workspace = "/workspace"
    ruby_files = find_ruby_files(workspace)
    
    print(f"Found {len(ruby_files)} Ruby files")
    
    # Analyze first 10 files
    for i, filepath in enumerate(ruby_files[:10]):
        rel_path = os.path.relpath(filepath, workspace)
        dates = get_file_dates(filepath)
        print(f"\n{i+1}. {rel_path}")
        for key, value in dates.items():
            print(f"   {key}: {value}")

if __name__ == '__main__':
    main()