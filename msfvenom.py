#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Compatibility wrapper for `msfvenom`.

Some tooling and docs reference `msfvenom.py`. The primary entrypoint is the
executable `msfvenom` in the repo root.
"""

from __future__ import annotations

import runpy
from pathlib import Path


def main() -> None:
    script = Path(__file__).resolve().with_name("msfvenom")
    runpy.run_path(str(script), run_name="__main__")


if __name__ == "__main__":
    main()

