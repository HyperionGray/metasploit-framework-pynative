#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ruby to Python Converter - Convenience Wrapper

This wrapper runs the canonical Ruby→Python converter at `ruby2py/convert.py`.
"""

import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
converter_dir = repo_root / "ruby2py"
converter_script = converter_dir / "convert.py"

if not converter_script.exists():
    print(f"ERROR: Converter not found at: {converter_script}", file=sys.stderr)
    sys.exit(1)

sys.path.insert(0, str(converter_dir))

try:
    from convert import main
except ImportError as e:
    print(f"ERROR: Failed to import converter: {e}", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    main()

