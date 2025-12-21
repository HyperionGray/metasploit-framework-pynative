#!/usr/bin/env python3
"""
Lightweight binary inspection helper for RE triage.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List


def run_cmd(cmd: List[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.stdout:
            return result.stdout.strip()
        return result.stderr.strip()
    except subprocess.SubprocessError as exc:
        return f"error: {exc}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick binary inspection")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--strings", type=int, default=20, help="Show first N strings")
    parser.add_argument("--symbols", type=int, default=10, help="Show first N text symbols")
    args = parser.parse_args()

    path = Path(args.binary)
    if not path.exists():
        print(f"[-] Binary not found: {path}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] File: {path}")
    print(run_cmd(["file", str(path)]))

    if shutil.which("checksec"):
        print("\n[+] checksec:")
        print(run_cmd(["checksec", "--file", str(path)]))
    else:
        print("\n[+] checksec: not available in PATH")

    if shutil.which("strings"):
        print(f"\n[+] strings (first {args.strings}):")
        out = run_cmd(["strings", str(path)])
        print("\n".join(out.splitlines()[: args.strings]))

    if shutil.which("nm"):
        print(f"\n[+] symbols (first {args.symbols} text symbols):")
        sym_out = run_cmd(["nm", str(path)])
        rows = [line for line in sym_out.splitlines() if " T " in line or " t " in line]
        print("\n".join(rows[: args.symbols]))


if __name__ == "__main__":
    main()
