#!/usr/bin/env python3
"""
Run AFL++ fuzzing with basic time-bounded execution.
"""

import argparse
import os
import shutil
import subprocess
import sys
from typing import List


def ensure_seed(input_dir: str) -> None:
    os.makedirs(input_dir, exist_ok=True)
    seed_path = os.path.join(input_dir, "seed")
    if not os.path.exists(seed_path):
        with open(seed_path, "w", encoding="utf-8") as handle:
            handle.write("SEED")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run AFL++ fuzzing")
    parser.add_argument("--target", required=True, help="Target binary")
    parser.add_argument("--input", default="./fuzzing/in", help="Input corpus directory")
    parser.add_argument("--output", default="./fuzzing/out", help="Output directory")
    parser.add_argument("--time", type=int, default=300, help="Timeout in seconds (0 for no timeout)")
    parser.add_argument("--args", default="", help="Additional args to pass after '--'")
    args = parser.parse_args()

    if not shutil.which("afl-fuzz"):
        print("[-] afl-fuzz not found in PATH", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(args.target) or not os.access(args.target, os.X_OK):
        print(f"[-] Target not executable: {args.target}", file=sys.stderr)
        sys.exit(1)

    ensure_seed(args.input)
    os.makedirs(args.output, exist_ok=True)

    cmd: List[str] = [
        "afl-fuzz",
        "-i",
        args.input,
        "-o",
        args.output,
        "--",
        args.target,
    ]
    if args.args:
        cmd.extend(args.args.split())

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, timeout=None if args.time == 0 else args.time, check=True)
    except subprocess.TimeoutExpired:
        print("[*] AFL++ run reached timeout; stopping")
    except subprocess.CalledProcessError as exc:
        print(f"[-] afl-fuzz failed: {exc}", file=sys.stderr)
        sys.exit(exc.returncode or 1)

    print(f"[+] Results in: {args.output}")


if __name__ == "__main__":
    main()
