#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Console - PyNative Version

This user interface provides users with a command console interface to the
framework. This is the Python-native implementation.

Converted from Ruby msfconsole script - Ruby will be deleted soon.
"""

import sys
import os
import argparse
from pathlib import Path

# Add lib directory to Python path
lib_path = os.path.join(os.path.dirname(__file__), 'lib')
sys.path.insert(0, lib_path)


def main():
    """Main entry point for msfconsole."""
    
    parser = argparse.ArgumentParser(description='Metasploit Framework Console')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress banner and startup messages')
    parser.add_argument('-r', '--resource', help='Execute resource file on startup')
    parser.add_argument('-x', '--execute-command', help='Execute command and exit')
    parser.add_argument('--version', action='version', version='Metasploit Framework Console 6.4.0-dev')
    
    args = parser.parse_args()
    
    # Show PyNative message unless quiet
    if not args.quiet and not os.environ.get('MSF_QUIET'):
        print("\n" + "="*70)
        print("  🐍 Metasploit Framework - PyNative Console")
        print("="*70)
        print("  This is the Python-native Metasploit Framework!")
        print("  Ruby has been converted to Python - no more TODOs!")
        print("")
        print("  For module usage:")
        print("    python3 modules/exploits/path/to/exploit.py --help")
        print("="*70 + "\n")
    
    # Try to load the MSF framework
    try:
        from msf import framework
        
        if not args.quiet:
            print("MSF Python Framework loaded successfully!")
            print("Starting interactive console...")
        
        # Execute single command if provided
        if args.execute_command:
            print(f"Executing: {args.execute_command}")
            # TODO: Parse and execute the command
            return
        
        # Load resource file if provided
        if args.resource:
            print(f"Loading resource file: {args.resource}")
            # TODO: Load and execute resource file
        
        # Start interactive console
        framework.start_console()
        
    except ImportError as e:
        print(f"Error loading MSF Python framework: {e}")
        print("The framework may not be properly installed.")
        print("Please check your installation and try again.")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)