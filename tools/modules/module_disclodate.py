#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Disclosure Date Utility
Port of tools/modules/module_disclodate.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists each module by its disclosure date
"""

import sys
import argparse
import re
from datetime import datetime


FILTERS = ['all', 'exploit', 'payload', 'post', 'nop', 'encoder', 'auxiliary']


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
        self.rows.sort(key=lambda x: x[column_index] if x[column_index] else '')
    
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


def parse_date(date_str):
    """Parse date string in YYYY-MM-DD format"""
    try:
        parts = date_str.split('-')
        if len(parts) == 3:
            year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
            return datetime(year, month, day)
    except (ValueError, IndexError):
        pass
    return None


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Metasploit Script for Displaying Module Disclosure Date Information.'
    )
    parser.add_argument(
        '-s', '--sort',
        action='store_true',
        help='Sort by Disclosure Date instead of Module Type'
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
        '-n', '--no-null',
        action='store_true',
        help='Filter out modules that have no Disclosure Date listed'
    )
    parser.add_argument(
        '-d', '--start-date',
        type=str,
        help='Start of Date Range YYYY-MM-DD'
    )
    parser.add_argument(
        '-D', '--end-date',
        type=str,
        help='End of Date Range YYYY-MM-DD'
    )
    parser.add_argument(
        'pattern',
        nargs='?',
        help='RegEx pattern to match against module names'
    )
    
    args = parser.parse_args()
    
    if args.sort:
        print("Sorting by Disclosure Date")
    if args.reverse:
        print("Reverse Sorting")
    if args.filter != 'All':
        print(f"Module Filter: {args.filter}")
    if args.no_null:
        print("Excluding Null dates")
    
    # Parse date range
    startdate = datetime.min
    enddate = datetime(2525, 1, 1)
    
    if args.start_date:
        parsed = parse_date(args.start_date)
        if parsed:
            startdate = parsed
            print(f"Start Date: {startdate.strftime('%Y-%m-%d')}")
        else:
            print(f"Invalid Start Date: {args.start_date}")
            sys.exit(1)
    
    if args.end_date:
        parsed = parse_date(args.end_date)
        if parsed:
            enddate = parsed
            print(f"End Date: {enddate.strftime('%Y-%m-%d')}")
        else:
            print(f"Invalid End Date: {args.end_date}")
            sys.exit(1)
    
    # Compile regex pattern if provided
    match_pattern = None
    if args.pattern:
        try:
            match_pattern = re.compile(args.pattern)
        except re.error as e:
            print(f"Invalid regex pattern: {e}", file=sys.stderr)
            sys.exit(1)
    
    indent = 2
    
    # Initialize framework options
    # NOTE: This would need actual framework initialization
    # framework_opts = {'DisableDatabase': True}
    # if args.filter.lower() != 'all':
    #     framework_opts['module_types'] = [args.filter.lower()]
    
    # Create table
    tbl = Table(
        header='Module References',
        indent=indent,
        columns=['Module', 'Disclosure Date']
    )
    
    # NOTE: The actual framework iteration would go here
    # This is a placeholder that would need to be implemented based on
    # how the Python version of Metasploit is structured
    
    # Example pseudo-code for what the implementation would look like:
    # framework = initialize_framework(framework_opts)
    # for name, mod in framework.modules.items():
    #     # Skip if pattern doesn't match
    #     if match_pattern and not match_pattern.search(name):
    #         continue
    #     
    #     module_instance = mod()
    #     disclosure_date = module_instance.disclosure_date
    #     
    #     if disclosure_date is None:
    #         if args.no_null:
    #             tbl.add_row([module_instance.fullname, ''])
    #     else:
    #         # Convert to datetime if needed
    #         if isinstance(disclosure_date, str):
    #             disclosure_date = parse_date(disclosure_date)
    #         
    #         if disclosure_date and startdate <= disclosure_date <= enddate:
    #             tbl.add_row([module_instance.fullname, disclosure_date.strftime('%Y-%m-%d')])
    
    # Sort if requested
    if args.sort:
        tbl.sort_rows(1)
    
    if args.reverse:
        tbl.sort_rows(1)
        tbl.reverse_rows()
    
    print(str(tbl))


if __name__ == '__main__':
    main()
