#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler - Convenience Wrapper

This is a convenience wrapper that imports and runs the canonical transpiler
located at ruby2py/py2ruby/transpiler.py.

For direct usage, you can also run:
    python3 ruby2py/py2ruby/transpiler.py [args]

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import sys
from pathlib import Path

# Add ruby2py directory to path to import the canonical transpiler
ruby2py_path = Path(__file__).resolve().parent.parent / "ruby2py" / "py2ruby"

if not ruby2py_path.exists():
    print(f"ERROR: Canonical transpiler not found at: {ruby2py_path}", file=sys.stderr)
    print("Expected location: ruby2py/py2ruby/transpiler.py", file=sys.stderr)
    print("Please ensure the repository structure is intact.", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(ruby2py_path))

try:
    # Import main function from the canonical transpiler
    from transpiler import main
except ImportError as e:
    print(f"ERROR: Failed to import canonical transpiler: {e}", file=sys.stderr)
    print(f"Expected location: {ruby2py_path / 'transpiler.py'}", file=sys.stderr)
    print("Please ensure ruby2py/py2ruby/transpiler.py exists.", file=sys.stderr)
    sys.exit(1)

if __name__ == '__main__':
    main()
