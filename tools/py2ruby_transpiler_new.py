#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler - Refactored Version

A modular transpiler that converts Python code to Ruby, now refactored
into smaller, focused components for better maintainability.

This replaces the original monolithic transpiler with a cleaner architecture.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import sys
import argparse
from pathlib import Path

# Import the refactored transpiler components
try:
    from .py2ruby_transpiler_refactored import (
        PythonToRubyTranspiler,
        transpile_python_to_ruby,
        transpile_file,
        main
    )
except ImportError:
    # Fallback for direct execution
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    from py2ruby_transpiler_refactored import (
        PythonToRubyTranspiler,
        transpile_python_to_ruby,
        transpile_file,
        main
    )

# Export the main functions for backward compatibility
__all__ = [
    'PythonToRubyTranspiler',
    'transpile_python_to_ruby', 
    'transpile_file',
    'main'
]

if __name__ == '__main__':
    main()