#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Targets Utility
Port of tools/modules/module_targets.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists all modules with their targets
"""

import sys
import argparse
import re


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
        description='Metasploit Script for Displaying Module Target information.'
    )
    parser.add_argument(
        '-s', '--sort',
        action='store_true',
        help='Sort by Target instead of Module Type'
    )
    parser.add_argument(
        '-r', '--reverse',
        action='store_true',
        help='Reverse Sort'
    )
    parser.add_argument(
        '-x', '--filter',
        type=str,
        help='String or RegEx to try and match against the Targets field'
    )
    
    args = parser.parse_args()
    
    if args.sort:
        print("Sorting by Target")
    if args.reverse:
        print("Reverse Sorting")
    if args.filter:
        print(f"Filter: {args.filter}")
    
    indent = 4
    
    # Initialize framework
    # NOTE: This would need actual framework initialization
    # framework = initialize_framework({'DisableDatabase': True})
    
    # Create table
    tbl = Table(
        header='Module Targets',
        indent=indent,
        columns=['Module name', 'Target']
    )
    
    # NOTE: The actual framework iteration would go here
    # This is a placeholder that would need to be implemented based on
    # how the Python version of Metasploit is structured
    
    # Example pseudo-code for what the implementation would look like:
    # all_modules = framework.exploits
    # filter_regex = re.compile(args.filter) if args.filter else None
    # 
    # for name, mod in all_modules.items():
    #     module_instance = mod()
    #     for target in module_instance.targets:
    #         if not filter_regex or filter_regex.search(target.name):
    #             tbl.add_row([module_instance.fullname, target.name])
    
    # Sort if requested
    if args.sort:
        tbl.sort_rows(1)
    
    if args.reverse:
        tbl.sort_rows(1)
        tbl.reverse_rows()
    
    print(str(tbl))


if __name__ == '__main__':
    main()
