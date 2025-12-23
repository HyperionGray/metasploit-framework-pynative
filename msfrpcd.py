#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Msfrpcd - Python Version

Wrapper script for msfrpcd.

Converted from Ruby msfrpcd script.
"""

import sys
import os
from pathlib import Path


def main():
    """Main entry point for msfrpcd."""
    
    # Get the repo root
    repo_root = Path(__file__).parent.resolve()
    
    # For now, delegate to the Ruby version if it exists
    ruby_script = repo_root / "msfrpcd"
    if ruby_script.exists():
        try:
            # Execute the Ruby version with all arguments
            os.execv(str(ruby_script), ['msfrpcd'] + sys.argv[1:])
        except Exception as e:
            print(f"Error executing Ruby msfrpcd: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Ruby msfrpcd not found", file=sys.stderr)
        print("TODO: Implement native Python version", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)
