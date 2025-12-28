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
ruby2py_path = Path(__file__).parent.parent / "ruby2py" / "py2ruby"
sys.path.insert(0, str(ruby2py_path))

# Import main function from the canonical transpiler
from transpiler import main

if __name__ == '__main__':
    main()
