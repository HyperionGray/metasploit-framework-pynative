#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MSF Database Web Service - Python Version

Manages the Metasploit Framework database web service.

Converted from Ruby tools/dev/msfdb_ws script.
"""

import sys
import os
from pathlib import Path


def main():
    """Main entry point for msfdb_ws."""
    
    # Get the repo root
    repo_root = Path(__file__).parent.parent.parent.resolve()
    
    # For now, delegate to the Ruby version if it exists
    ruby_script = repo_root / "tools" / "dev" / "msfdb_ws"
    if ruby_script.exists():
        try:
            # Execute the Ruby version with all arguments
            os.execv(str(ruby_script), ['msfdb_ws'] + sys.argv[1:])
        except Exception as e:
            print(f"Error executing Ruby msfdb_ws: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Error: Ruby msfdb_ws not found", file=sys.stderr)
        print("TODO: Implement native Python version", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborting...")
        sys.exit(1)
