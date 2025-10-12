#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Committer Count Utility
Port of tools/modules/committer_count.rb to Python

The committer_count.py is a way to tell who's been active over the last
given period. It's of course, quite coarse -- someone with 10 commits in a day
may or may not be more productive than someone with 3, but over long enough
periods, it's an okay metric to measure involvement with the project, since
large and small commits will tend to average out.

Note that this includes merge commits by default (which usually means at least
code review happened, so it's still a measure of work). You can get different
stats by ignoring merge commits, once option parsing is implemented.

Usage: ./committer_count.py 2011-01-01 | head -10 # Since a particular date
       ./committer_count.py 1y   | head -10       # Last year
       ./committer_count.py 6m   | head -10       # Last six months
       ./committer_count.py 12w  | head -10       # Last twelve weeks
       ./committer_count.py 100d | head -10       # Last hundred days

History with colors and e-mail addresses (respecting .mailmap):
git log --pretty=format:"%C(white)%ad %C(yellow)%h %Cblue'%aN' <%aE> %Cgreen%f%Creset" --date=short
"""

import sys
import re
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict


class GitLogLine:
    """Container for git log line information"""
    def __init__(self, date, hash_val, author, message):
        self.date = date
        self.hash = hash_val
        self.author = author
        self.message = message


def parse_date(date):
    """Parse date string and return formatted date"""
    # Check for year pattern (e.g., "1y", "2years")
    match = re.match(r'([0-9]+)y(?:ear)?s?', date)
    if match:
        years = int(match.group(1))
        seconds = years * (60 * 60 * 24 * 365.25)
        calc_date = datetime.now() - timedelta(seconds=seconds)
        return calc_date.strftime("%Y-%m-%d")
    
    # Check for month pattern (e.g., "6m", "12months")
    match = re.match(r'([0-9]+)m(?:onth)?s?', date)
    if match:
        months = int(match.group(1))
        seconds = months * (60 * 60 * 24 * (365.25 / 12))
        calc_date = datetime.now() - timedelta(seconds=seconds)
        return calc_date.strftime("%Y-%m-%d")
    
    # Check for week pattern (e.g., "12w", "4weeks")
    match = re.match(r'([0-9]+)w(?:eek)?s?', date)
    if match:
        weeks = int(match.group(1))
        seconds = weeks * (60 * 60 * 24 * 7)
        calc_date = datetime.now() - timedelta(seconds=seconds)
        return calc_date.strftime("%Y-%m-%d")
    
    # Check for day pattern (e.g., "100d", "30days")
    match = re.match(r'([0-9]+)d(?:ay)?s?', date)
    if match:
        days = int(match.group(1))
        seconds = days * (60 * 60 * 24)
        calc_date = datetime.now() - timedelta(seconds=seconds)
        return calc_date.strftime("%Y-%m-%d")
    
    # Otherwise parse as date
    try:
        parsed = datetime.strptime(date, "%Y-%m-%d")
        return parsed.strftime("%Y-%m-%d")
    except ValueError:
        # Try other formats
        try:
            parsed = datetime.fromisoformat(date)
            return parsed.strftime("%Y-%m-%d")
        except:
            return date


def main():
    """Main function"""
    # Default to a day before the first SVN commit
    date = sys.argv[1] if len(sys.argv) > 1 else "2005-03-22"
    calc_date = parse_date(date)
    
    # Get git log history
    try:
        git_cmd = subprocess.run(
            ['git', 'log', '--pretty=format:%ad %h \'%aN\' %f', '--date=short', '--date-order'],
            capture_output=True,
            text=True,
            check=True
        )
        history = git_cmd.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running git log: {e}", file=sys.stderr)
        sys.exit(1)
    
    recent_history = []
    commits_by_author = defaultdict(list)
    
    # Parse git log output
    for line in history.split('\n'):
        # Match format: YYYY-MM-DD HASH 'AUTHOR' MESSAGE
        match = re.match(r'^([^\s+]+)\s(.{7,})\s\'(.*)\'\s(.*)[\r\n]*$', line)
        if match:
            log_date, log_hash, log_author, log_message = match.groups()
            if log_date == calc_date:
                break
            recent_history.append(GitLogLine(log_date, log_hash, log_author, log_message))
    
    # Group commits by author
    for logline in recent_history:
        commits_by_author[logline.author].append(logline.message)
    
    # Print results
    print(f"Commits since {calc_date}")
    print("-" * 50)
    
    # Sort by commit count (descending)
    for author, commits in sorted(commits_by_author.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"{author:<25} {len(commits):>3}")


if __name__ == '__main__':
    main()
