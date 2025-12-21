#!/usr/bin/env python3
"""
Build a binary instrumented for AFL++ fuzzing.
"""

import argparse
import os
import shutil
import subprocess
import sys
from typing import List


def choose_compiler(use_lto: bool) -> str:
    if use_lto and shutil.which("afl-clang-lto"):
        return "afl-clang-lto"
    if shutil.which("afl-clang-fast"):
        return "afl-clang-fast"
    return "clang"


def build_command(compiler: str, source: str, output: str, extra_flags: List[str]) -> List[str]:
    base = [compiler, "-g"]
    # Keep basic ASan by default for better crash fidelity
    if "afl-clang" in compiler or compiler == "clang":
        base.append("-fsanitize=address")
    return base + extra_flags + [source, "-o", output]


def main() -> None:
    parser = argparse.ArgumentParser(description="Build AFL++ instrumented target")
    parser.add_argument("--source", required=True, help="Source file to compile")
    parser.add_argument("--output", help="Output binary path")
    parser.add_argument("--use-lto", action="store_true", help="Prefer afl-clang-lto if available")
    parser.add_argument("--extra-flags", default="", help="Additional compiler flags (space separated)")
    args = parser.parse_args()

    if not os.path.isfile(args.source):
        print(f"[-] Source file not found: {args.source}", file=sys.stderr)
        sys.exit(1)

    compiler = choose_compiler(args.use_lto)
    if not shutil.which(compiler):
        print(f"[-] Compiler not available: {compiler}", file=sys.stderr)
        sys.exit(1)

    base_name = os.path.splitext(os.path.basename(args.source))[0]
    output = args.output or (f"{base_name}_afl_lto" if "lto" in compiler else f"{base_name}_afl")
    extra = args.extra_flags.split() if args.extra_flags else []
    cmd = build_command(compiler, args.source, output, extra)

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[-] Build failed: {exc}", file=sys.stderr)
        sys.exit(exc.returncode or 1)

    print(f"[+] Built AFL++ target: {output}")


if __name__ == "__main__":
    main()
