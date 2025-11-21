#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Commits Utility
Port of tools/modules/module_commits.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

Check the commit history of a module or tree of modules
and sort by number of commits.

Usage: tools/module_commits.py [module dir | module fname]
"""

import sys
import os
import re
import subprocess
from pathlib import Path
from collections import defaultdict


class GitLogLine:
    """Container for git log line information"""
    def __init__(self, date, hash_val, author, message):
        self.date = date
        self.hash = hash_val
        self.author = author
        self.message = message


class CommitHistory:
    """Container for commit history information"""
    def __init__(self, fname, total, authors):
        self.fname = fname
        self.total = total
        self.authors = authors


def check_commit_history(fname):
    """Check commit history for a file"""
    try:
        git_cmd = subprocess.run(
            ['git', 'log', '--pretty=format:%ad %h \'%aN\' %f', '--date=short', '--date-order', fname],
            capture_output=True,
            text=True,
            check=True
        )
        git_output = git_cmd.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running git log for {fname}: {e}", file=sys.stderr)
        return None
    
    commit_history = []
    commits_by_author = defaultdict(list)
    
    # Parse git log output
    for line in git_output.split('\n'):
        if not line:
            continue
        # Match format: YYYY-MM-DD HASH 'AUTHOR' MESSAGE
        match = re.match(r'^([^\s+]+)\s(.{7,})\s\'(.*)\'\s(.*)[\r\n]*$', line)
        if match:
            log_date, log_hash, log_author, log_message = match.groups()
            commit_history.append(GitLogLine(log_date, log_hash, log_author, log_message))
    
    # Group commits by author
    for logline in commit_history:
        commits_by_author[logline.author].append(logline.message)
    
    # Print commit details
    print(f"Commits for {fname} {len(commit_history)}")
    print("-" * 72)
    
    # Sort by commit count (descending)
    for author, commits in sorted(commits_by_author.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{author:<25} {len(commits):>3}")
    
    return CommitHistory(fname, len(commit_history), commits_by_author)


def find_module_files(directory):
    """Find all module files (Ruby or Python) in directory"""
    module_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.rb', '.py')):
                filepath = os.path.join(root, file)
                if os.path.isfile(filepath) and os.access(filepath, os.R_OK):
                    module_files.append(filepath)
    return module_files


def main():
    """Main function"""
    # Determine base directory
    script_path = os.path.abspath(__file__)
    while os.path.islink(script_path):
        script_path = os.path.abspath(os.readlink(script_path))
    msfbase = os.path.abspath(os.path.join(os.path.dirname(script_path), '..', '..'))
    
    # Get directory from args or use default
    dir_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(msfbase, "modules", "exploits")
    
    if not os.path.exists(dir_path) or not os.access(dir_path, os.R_OK):
        print(f"Error: Need a readable filename or directory", file=sys.stderr)
        sys.exit(1)
    
    module_stats = []
    
    # Check if it's a file or directory
    if os.path.isfile(dir_path):
        result = check_commit_history(dir_path)
        if result:
            module_stats.append(result)
    else:
        # Find all module files
        module_files = find_module_files(dir_path)
        for fname in module_files:
            result = check_commit_history(fname)
            if result:
                module_stats.append(result)
    
    # Print sorted summary
    print("=" * 72)
    print("Sorted modules by commit counts")
    
    for module in sorted(module_stats, key=lambda m: m.total, reverse=True):
        print(f"{module.fname:<60} {module.total}")


if __name__ == '__main__':
    main()
