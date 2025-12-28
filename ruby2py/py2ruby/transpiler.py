#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler (Redirects to Modular Implementation)

This file redirects to the new modular transpiler implementation
located in tools/py2ruby/. The original monolithic code has been
refactored for better maintainability.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import sys
from pathlib import Path

# Add tools directory to path for imports
tools_path = Path(__file__).parent.parent.parent / 'tools'
sys.path.insert(0, str(tools_path))

try:
    from py2ruby import transpile_python_to_ruby, PythonToRubyTranspiler
    from py2ruby.__main__ import main, transpile_file
    
    print("🔄 Redirecting to modular transpiler implementation")
    print("   Location: tools/py2ruby/")
    print("   Benefits: Modular, maintainable, extensible")
    print()
    
except ImportError as e:
    print(f"❌ Error importing modular transpiler: {e}")
    print("Please ensure tools/py2ruby/ directory exists")
    sys.exit(1)

if __name__ == '__main__':
    main()