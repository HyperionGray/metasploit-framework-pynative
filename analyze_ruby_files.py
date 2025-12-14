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
        
        # Get filesystem modification time
        stat = os.stat(filepath)
        fs_mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
        
        return {
            'git_first': git_dates[0] if git_dates else None,
            'git_last': git_dates[-1] if git_dates else None,
            'fs_mtime': fs_mtime.isoformat()
        }
    except Exception as e:
        return {'error': str(e)}

def classify_by_date(date_str, cutoff_year=2020):
    """Classify file as pre or post cutoff year"""
    if not date_str:
        return 'unknown'
    
    try:
        # Parse various date formats
        if 'T' in date_str:
            date_obj = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        else:
            # Git format: 2021-01-15 10:30:45 -0500
            date_part = date_str.split()[0]
            date_obj = datetime.datetime.strptime(date_part, '%Y-%m-%d')
        
        return 'post-2020' if date_obj.year > cutoff_year else 'pre-2020'
    except:
        return 'unknown'

if __name__ == '__main__':
    print("Finding all Ruby files...")
    ruby_files = find_ruby_files('/workspace')
    print(f"Found {len(ruby_files)} Ruby files")
    
    print("\nAnalyzing dates...")
    results = {
        'pre-2020': [],
        'post-2020': [],
        'unknown': []
    }
    
    for i, filepath in enumerate(ruby_files):
        if i % 50 == 0:
            print(f"Processed {i}/{len(ruby_files)} files...")
        
        dates = get_file_dates(filepath)
        
        # Use git first commit date if available, otherwise git last, otherwise filesystem
        primary_date = dates.get('git_first') or dates.get('git_last') or dates.get('fs_mtime')
        classification = classify_by_date(primary_date)
        
        results[classification].append({
            'path': filepath,
            'dates': dates,
            'classification': classification
        })
    
    print(f"\nResults:")
    print(f"Pre-2020: {len(results['pre-2020'])} files")
    print(f"Post-2020: {len(results['post-2020'])} files") 
    print(f"Unknown: {len(results['unknown'])} files")
    
    # Save detailed results
    with open('/workspace/ruby_file_analysis.txt', 'w') as f:
        for category, files in results.items():
            f.write(f"\n=== {category.upper()} FILES ===\n")
            for file_info in files:
                f.write(f"{file_info['path']}\n")
                f.write(f"  Dates: {file_info['dates']}\n")
                f.write(f"  Classification: {file_info['classification']}\n\n")
    
    print(f"\nDetailed analysis saved to ruby_file_analysis.txt")
    
    # Show some examples
    print(f"\nSample post-2020 files:")
    for file_info in results['post-2020'][:5]:
        print(f"  {file_info['path']}")
    
    print(f"\nSample pre-2020 files:")
    for file_info in results['pre-2020'][:5]:
        print(f"  {file_info['path']}")