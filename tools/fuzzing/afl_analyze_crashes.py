#!/usr/bin/env python3
"""
List AFL++ crash artifacts and show brief hex dumps.
"""

import argparse
import os
import sys
from pathlib import Path


def list_crashes(crash_dir: Path, limit: int) -> None:
    crashes = [p for p in crash_dir.iterdir() if p.is_file() and p.name != "README.txt"]
    if not crashes:
        print("No crash files found.")
        return

    for idx, crash in enumerate(sorted(crashes)[:limit], 1):
        print(f"[{idx}] {crash}")
        try:
            data = crash.read_bytes()
            print("    Hexdump (first 64 bytes):", data[:64].hex())
        except OSError as exc:
            print(f"    Error reading file: {exc}")

    if len(crashes) > limit:
        print(f"... ({len(crashes) - limit} more not shown)")
    print(f"Total crashes: {len(crashes)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze AFL++ crashes directory")
    parser.add_argument("--crashes", default="./fuzzing/out/default/crashes", help="Crash directory")
    parser.add_argument("--limit", type=int, default=20, help="Number of crashes to show")
    args = parser.parse_args()

    crash_dir = Path(args.crashes)
    if not crash_dir.exists():
        print(f"[-] Crashes directory not found: {crash_dir}", file=sys.stderr)
        sys.exit(1)

    list_crashes(crash_dir, args.limit)


if __name__ == "__main__":
    main()
