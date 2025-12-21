#!/usr/bin/env python3
"""
Compile a target with common sanitizers or libFuzzer instrumentation.
"""

import argparse
import os
import shutil
import subprocess
import sys
from typing import List


SANITIZER_FLAGS = {
    "asan": ["-fsanitize=address"],
    "msan": ["-fsanitize=memory", "-fsanitize-memory-track-origins"],
    "ubsan": ["-fsanitize=undefined"],
    "tsan": ["-fsanitize=thread"],
    "libfuzzer": ["-fsanitize=fuzzer", "-fsanitize=address"],
}


def detect_compiler(source: str) -> str:
    """Choose clang++ for C++ sources, clang otherwise."""
    ext = os.path.splitext(source)[1].lower()
    if ext in {".cc", ".cpp", ".cxx"}:
        return "clang++"
    return "clang"


def build_command(compiler: str, source: str, output: str, sanitizer: str, extra: List[str]) -> List[str]:
    flags = SANITIZER_FLAGS[sanitizer]
    cmd = [compiler, "-g", "-O1", source, "-o", output] + flags + extra
    return cmd


def main() -> None:
    parser = argparse.ArgumentParser(description="Build with sanitizers or libFuzzer")
    parser.add_argument("--source", required=True, help="Source file to compile")
    parser.add_argument("--sanitizer", required=True, choices=SANITIZER_FLAGS.keys(), help="Sanitizer/target")
    parser.add_argument("--output", help="Output binary path")
    parser.add_argument("--extra-flags", default="", help="Additional compiler flags (space separated)")
    args = parser.parse_args()

    source = args.source
    if not os.path.isfile(source):
        print(f"[-] Source file not found: {source}", file=sys.stderr)
        sys.exit(1)

    compiler = detect_compiler(source)
    if not shutil.which(compiler):
        print(f"[-] {compiler} not found in PATH", file=sys.stderr)
        sys.exit(1)

    base_name = os.path.splitext(os.path.basename(source))[0]
    default_output = {
        "asan": f"{base_name}_asan",
        "msan": f"{base_name}_msan",
        "ubsan": f"{base_name}_ubsan",
        "tsan": f"{base_name}_tsan",
        "libfuzzer": f"{base_name}_fuzzer",
    }[args.sanitizer]
    output = args.output or default_output

    extra = args.extra_flags.split() if args.extra_flags else []
    cmd = build_command(compiler, source, output, args.sanitizer, extra)

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[-] Build failed: {exc}", file=sys.stderr)
        sys.exit(exc.returncode or 1)

    print(f"[+] Built {output} with {args.sanitizer.upper()}")


if __name__ == "__main__":
    main()
