#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler (Modular Implementation)

This file now uses the new modular transpiler implementation.
The original 977-line monolithic code has been refactored into
focused modules for better maintainability.

Original file size: 977 lines
New implementation: 6 focused modules, each < 200 lines

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import sys
import argparse
from pathlib import Path

# Import from the new modular implementation
try:
    from .py2ruby import transpile_python_to_ruby
    from .py2ruby.__main__ import transpile_file, main as modular_main
except ImportError:
    # Fallback for direct execution
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        from py2ruby import transpile_python_to_ruby
        from py2ruby.__main__ import transpile_file, main as modular_main
    except ImportError:
        print("❌ Error: Modular py2ruby implementation not found")
        print("Please ensure tools/py2ruby/ directory exists with all modules")
        sys.exit(1)


def main():
    """Main entry point - delegates to modular implementation."""
    print("🔄 Using modular Python to Ruby transpiler")
    print("   (Refactored from 977-line monolith to 6 focused modules)")
    print()
    return modular_main()


if __name__ == '__main__':
    main()