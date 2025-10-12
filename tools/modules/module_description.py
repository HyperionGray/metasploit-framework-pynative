#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Description Utility
Port of tools/modules/module_description.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists each module with its description
"""

import sys
import argparse


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
        self.rows.sort(key=lambda x: x[column_index])
    
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
        description='Metasploit Script for Displaying Module Descriptions.'
    )
    parser.add_argument(
        '-f', '--filter',
        choices=[f.capitalize() for f in FILTERS],
        default='All',
        help=f'Filter based on Module Type [{", ".join(f.capitalize() for f in FILTERS)}] (Default = All)'
    )
    
    args = parser.parse_args()
    
    if args.filter != 'All':
        print(f"Module Filter: {args.filter}")
    
    indent = 4
    
    # Initialize framework options
    # NOTE: This would need actual framework initialization
    # framework_opts = {'DisableDatabase': True}
    # if args.filter.lower() != 'all':
    #     framework_opts['module_types'] = [args.filter.lower()]
    
    # Create table
    tbl = Table(
        header='Module Descriptions',
        indent=indent,
        columns=['Module', 'Description']
    )
    
    # NOTE: The actual framework iteration would go here
    # This is a placeholder that would need to be implemented based on
    # how the Python version of Metasploit is structured
    
    # Example pseudo-code for what the implementation would look like:
    # framework = initialize_framework(framework_opts)
    # for name, mod in framework.modules.items():
    #     module_instance = mod()
    #     tbl.add_row([module_instance.fullname, module_instance.description])
    
    print(str(tbl))


if __name__ == '__main__':
    main()
