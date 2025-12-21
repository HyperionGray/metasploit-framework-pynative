#!/usr/bin/env python3
"""
Run a libFuzzer target with a corpus and time budget.
"""

import argparse
import os
import subprocess
import sys
from typing import List


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a libFuzzer binary")
    parser.add_argument("--target", required=True, help="Path to libFuzzer binary")
    parser.add_argument("--corpus", default="./corpus", help="Corpus directory (created if missing)")
    parser.add_argument("--time", type=int, default=60, help="Max total time (seconds)")
    parser.add_argument("--extra-args", default="", help="Additional arguments to pass to the fuzzer")
    args = parser.parse_args()

    if not os.path.isfile(args.target) or not os.access(args.target, os.X_OK):
        print(f"[-] Target not executable: {args.target}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(args.corpus, exist_ok=True)

    cmd: List[str] = [
        args.target,
        args.corpus,
        f"-max_total_time={args.time}",
        "-print_final_stats=1",
    ]
    if args.extra_args:
        cmd.extend(args.extra_args.split())

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        print(f"[-] libFuzzer run failed: {exc}", file=sys.stderr)
        sys.exit(exc.returncode or 1)

    print("[+] libFuzzer run complete")


if __name__ == "__main__":
    main()
