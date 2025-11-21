#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module Ports Utility
Port of tools/modules/module_ports.rb to Python

This module requires Metasploit: https://metasploit.com/download
Current source: https://github.com/rapid7/metasploit-framework

This script lists each module by the default ports it uses
"""

import sys


def main():
    """Main function"""
    # NOTE: This would need actual framework initialization
    # Initialize the simplified framework instance
    # framework = initialize_framework({'DisableDatabase': True})
    
    # XXX: merging module sets together for different module types could lead to unforeseen issues
    # all_modules = framework.exploits | framework.auxiliary
    all_ports = {}
    
    # NOTE: The actual framework iteration would go here
    # This is a placeholder that would need to be implemented based on
    # how the Python version of Metasploit is structured
    
    # Example pseudo-code for what the implementation would look like:
    # for name, mod in all_modules.items():
    #     module_instance = mod()
    #     ports = []
    #     
    #     # Check for RPORT datastore option
    #     if 'RPORT' in module_instance.datastore:
    #         ports.append(module_instance.datastore['RPORT'])
    #     
    #     # Check for autofilter_ports
    #     if hasattr(module_instance, 'autofilter_ports'):
    #         for rport in module_instance.autofilter_ports():
    #             ports.append(rport)
    #     
    #     # Convert to integers, remove duplicates, and sort
    #     ports = list(set(int(p) for p in ports))
    #     ports.sort()
    #     
    #     for rport in ports:
    #         # Just record the first occurrence
    #         if rport not in all_ports:
    #             all_ports[rport] = module_instance.fullname
    
    # Sort and print results
    for port in sorted(all_ports.keys()):
        module_name = all_ports[port]
        print(f"{port:>5} # {module_name}")
    
    if not all_ports:
        print("# This script requires framework integration to list module ports", file=sys.stderr)
        print("# Placeholder implementation - actual framework needed", file=sys.stderr)


if __name__ == '__main__':
    main()
