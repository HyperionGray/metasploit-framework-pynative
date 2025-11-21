#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Author Utility
Port of tools/modules/module_author.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists each module by its author(s) and the number of modules per author
"""

import sys
import os
import json
import argparse
import re


FILENAME = 'db/modules_metadata_base.json'
FILTERS = ['all', 'exploit', 'payload', 'post', 'nop', 'encoder', 'auxiliary', 'evasion']


class Table:
    """Simple table formatter for output"""
    
    def __init__(self, header, indent, columns):
        self.header = header
        self.indent = indent
        self.columns = columns
        self.rows = []
    
    def add_row(self, row):
        """Add a row to the table"""
        self.rows.append(row)
    
    def sort_rows(self, column_index):
        """Sort rows by specified column"""
        self.rows.sort(key=lambda x: x[column_index])
    
    def reverse_rows(self):
        """Reverse the order of rows"""
        self.rows.reverse()
    
    def __str__(self):
        """Convert table to string representation"""
        if not self.rows:
            return f"{' ' * self.indent}{self.header}\n{' ' * self.indent}No data"
        
        # Calculate column widths
        col_widths = [len(col) for col in self.columns]
        for row in self.rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build header
        result = f"{' ' * self.indent}{self.header}\n"
        result += ' ' * self.indent
        result += ' | '.join(col.ljust(col_widths[i]) for i, col in enumerate(self.columns))
        result += '\n'
        result += ' ' * self.indent + '-' * (sum(col_widths) + 3 * (len(self.columns) - 1))
        result += '\n'
        
        # Build rows
        for row in self.rows:
            result += ' ' * self.indent
            result += ' | '.join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row))
            result += '\n'
        
        return result


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Metasploit Script for Displaying Module Author information.'
    )
    parser.add_argument(
        '-s', '--sort',
        action='store_true',
        help='Sort by Author'
    )
    parser.add_argument(
        '-r', '--reverse',
        action='store_true',
        help='Reverse Sort'
    )
    parser.add_argument(
        '-f', '--filter',
        choices=[f.capitalize() for f in FILTERS],
        default='All',
        help=f'Filter based on Module Type [{", ".join(f.capitalize() for f in FILTERS)}] (Default = All)'
    )
    parser.add_argument(
        '-x', '--regex',
        type=str,
        help='String or RegEx to try and match against the Author Field'
    )
    
    args = parser.parse_args()
    
    if args.sort:
        print("Sorting by Author")
    if args.reverse:
        print("Reverse Sorting")
    if args.filter != 'All':
        print(f"Module Filter: {args.filter}")
    if args.regex:
        print(f"Regex: {args.regex}")
    
    indent = 4
    
    # Create main table for module references
    tbl = Table(
        header='Module References',
        indent=indent,
        columns=['Module', 'Reference']
    )
    
    names = {}
    
    # Load modules metadata
    try:
        with open(FILENAME, 'r') as f:
            local_modules = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find {FILENAME}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {FILENAME}: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Process modules
    filter_lower = args.filter.lower()
    regex = re.compile(args.regex) if args.regex else None
    
    for module_key, local_module in local_modules.items():
        # Filter by module type
        if filter_lower != 'all' and local_module.get('type') != filter_lower:
            continue
        
        # Process authors
        authors = local_module.get('author', [])
        for author in authors:
            # Filter by regex if specified
            if regex is None or regex.search(author):
                tbl.add_row([local_module['fullname'], author])
                names[author] = names.get(author, 0) + 1
    
    # Sort if requested
    if args.sort:
        tbl.sort_rows(1)
    
    if args.reverse:
        tbl.sort_rows(1)
        tbl.reverse_rows()
    
    print(str(tbl))
    
    # Create count table
    count_tbl = Table(
        header='Module Count by Author',
        indent=indent,
        columns=['Count', 'Name']
    )
    
    # Sort by count (descending)
    for name in sorted(names.keys(), key=lambda n: names[n], reverse=True):
        count_tbl.add_row([str(names[name]), name])
    
    print()
    print(str(count_tbl))


if __name__ == '__main__':
    main()
