#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module License Utility
Port of tools/modules/module_license.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists each module by its licensing terms
"""

import sys
import argparse


FILTERS = ['all', 'exploit', 'payload', 'post', 'nop', 'encoder', 'auxiliary']

# License constants (would be defined in the framework)
MSF_LICENSE = 'MSF_LICENSE'
GPL_LICENSE = 'GPL_LICENSE'
BSD_LICENSE = 'BSD_LICENSE'
ARTISTIC_LICENSE = 'ARTISTIC_LICENSE'


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


def lic_short(license_val):
    """Convert license to short form"""
    # Handle array of licenses
    if isinstance(license_val, (list, tuple)):
        license_val = license_val[0] if license_val else None
    
    if license_val == MSF_LICENSE:
        return 'MSF'
    elif license_val == GPL_LICENSE:
        return 'GPL'
    elif license_val == BSD_LICENSE:
        return 'BSD'
    elif license_val == ARTISTIC_LICENSE:
        return 'ART'
    else:
        return 'UNK'


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Metasploit Script for Displaying Module License information.'
    )
    parser.add_argument(
        '-s', '--sort',
        action='store_true',
        help='Sort by License instead of Module Type'
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
        help='String or RegEx to try and match against the License Field'
    )
    
    args = parser.parse_args()
    
    if args.sort:
        print("Sorting by License")
    if args.reverse:
        print("Reverse Sorting")
    if args.filter != 'All':
        print(f"Module Filter: {args.filter}")
    if args.regex:
        print(f"Regex: {args.regex}")
    
    indent = 4
    
    # Initialize framework options
    # NOTE: This would need actual framework initialization
    # framework_opts = {'DisableDatabase': True}
    # if args.filter.lower() != 'all':
    #     framework_opts['module_types'] = [args.filter.lower()]
    
    # Create table
    tbl = Table(
        header='Licensed Modules',
        indent=indent,
        columns=['License', 'Type', 'Name']
    )
    
    # NOTE: The actual framework iteration would go here
    # This is a placeholder that would need to be implemented based on
    # how the Python version of Metasploit is structured
    
    # Example pseudo-code for what the implementation would look like:
    # framework = initialize_framework(framework_opts)
    # for name, mod in framework.modules.items():
    #     module_instance = mod()
    #     lictype = lic_short(module_instance.license)
    #     if not args.regex or re.search(args.regex, lictype):
    #         tbl.add_row([lictype, mod.type.capitalize(), name])
    
    # Sort if requested
    if args.sort:
        tbl.sort_rows(0)
    
    if args.reverse:
        tbl.sort_rows(1)
        tbl.reverse_rows()
    
    print(str(tbl))


if __name__ == '__main__':
    main()
