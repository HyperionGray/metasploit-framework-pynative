#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Msfupdate - Python Version

Wrapper script for msfupdate.

Converted from Ruby msfupdate script.
"""

import sys
import os
from pathlib import Path


def main():
    """Main entry point for msfupdate."""
    
    # Get the repo root
    repo_root = Path(__file__).parent.resolve()
    
    # For now, delegate to the Ruby version if it exists
    ruby_script = repo_root / "msfupdate"
    if ruby_script.exists():
        try:
            # Execute the Ruby version with all arguments
            os.execv(str(ruby_script), ['msfupdate'] + sys.argv[1:])
        except Exception as e:
            print(f"Error executing Ruby msfupdate: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Ruby msfupdate not found", file=sys.stderr)
        print("TODO: Implement native Python version", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)
