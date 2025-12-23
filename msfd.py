#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Metasploit Framework Daemon - Python Version

This script starts the Metasploit Framework daemon which allows remote
connections to the framework.

Converted from Ruby msfd script.
"""

import sys
import os
from pathlib import Path


def main():
    """Main entry point for msfd."""
    
    # Get the repo root
    repo_root = Path(__file__).parent.resolve()
    
    # For now, delegate to the Ruby msfd if it exists
    ruby_msfd = repo_root / "msfd"
    if ruby_msfd.exists():
        try:
            # Execute the Ruby version with all arguments
            os.execv(str(ruby_msfd), ['msfd'] + sys.argv[1:])
        except Exception as e:
            print(f"Error executing Ruby msfd: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Ruby msfd not found", file=sys.stderr)
        print("TODO: Implement native Python daemon", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)
