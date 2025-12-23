#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Console - Python Version

This user interface provides users with a command console interface to the
framework. This is a Python wrapper that can invoke the Ruby console or
provide native Python functionality.

Converted from Ruby msfconsole script.
"""

import sys
import os
import subprocess
from pathlib import Path


def main():
    """Main entry point for msfconsole."""
    
    # Show informational message about Python-native alternative
    if not os.environ.get('MSF_QUIET') and '-q' not in sys.argv and '--quiet' not in sys.argv:
        print("\n" + "="*70)
        print("  Metasploit Framework - Console (Python Wrapper)")
        print("="*70)
        print("  TIP: For native Python modules, use:")
        print("    python3 modules/exploits/path/to/exploit.py --help")
        print("")
        print("  Conversion tools available in: tools/")
        print("="*70 + "\n")
    
    # Get the repo root
    repo_root = Path(__file__).parent.resolve()
    
    # For now, delegate to the Ruby msfconsole if it exists
    ruby_msfconsole = repo_root / "msfconsole"
    if ruby_msfconsole.exists():
        try:
            # Execute the Ruby version with all arguments
            os.execv(str(ruby_msfconsole), ['msfconsole'] + sys.argv[1:])
        except Exception as e:
            print(f"Error executing Ruby msfconsole: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Ruby msfconsole not found", file=sys.stderr)
        print("TODO: Implement native Python console", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)