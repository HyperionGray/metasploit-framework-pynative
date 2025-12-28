#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python to Ruby Transpiler (Backup - Redirects to Modular Implementation)

This backup file now redirects to the new modular transpiler implementation.
The original 977-line monolithic code has been refactored into focused modules.

Author: Metasploit Framework Python Migration Team
License: BSD-3-Clause
"""

import sys
from pathlib import Path

# Add tools directory to path for imports
tools_path = Path(__file__).parent.parent.parent / 'tools'
sys.path.insert(0, str(tools_path))

def main():
    print("📁 This is a backup/legacy location")
    print("🔄 Redirecting to modular transpiler implementation")
    print("   Active location: tools/py2ruby/")
    print("   This backup preserved for compatibility")
    print()
    
    try:
        from py2ruby.__main__ import main as modular_main
        return modular_main()
    except ImportError as e:
        print(f"❌ Error importing modular transpiler: {e}")
        print("Please ensure tools/py2ruby/ directory exists")
        return 1

if __name__ == '__main__':
    sys.exit(main())