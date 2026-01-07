#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
run_elf_phased.py

Runs an ELF as a normal subprocess, but "time-slices" execution by pausing and
resuming the process group, running some benign Python steps in-between.

This is NOT an in-memory loader and does not execute raw bytes; it just controls
an external process via SIGSTOP/SIGCONT.
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def _print_between_step(step: str, cwd: Path) -> None:
    if step == "pwd":
        print(f"[py] cwd={cwd}")
        return
    if step == "listdir":
        try:
            entries = sorted(os.listdir(cwd))
        except Exception as e:
            print(f"[py] listdir failed: {e}")
            return
        print("[py] listdir:")
        for name in entries[:200]:
            print(f"  {name}")
        if len(entries) > 200:
            print(f"  ... ({len(entries) - 200} more)")
        return
    if step == "uname":
        u = platform.uname()
        print(f"[py] uname: {u.system} {u.release} {u.machine}")
        return
    if step == "env":
        keys = ["USER", "HOME", "SHELL", "PATH", "PWD"]
        print("[py] env (subset):")
        for k in keys:
            v = os.environ.get(k)
            if v is not None:
                print(f"  {k}={v}")
        return
    if step == "sleep":
        time.sleep(0.25)
        return
    raise ValueError(f"Unknown between-step: {step}")


def _killpg(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        pass


def _wait_stopped(pid: int, timeout_s: float = 5.0) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            wpid, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
        except ChildProcessError:
            return False
        if wpid == 0:
            time.sleep(0.01)
            continue
        return os.WIFSTOPPED(status)
    return False


def main(argv: list[str] | None = None) -> int:
    if os.name != "posix":
        print("This script requires a POSIX OS (Linux/macOS).", file=sys.stderr)
        return 2

    # Be friendly in pipelines like `... | head` by exiting quietly on SIGPIPE.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="Run an ELF in time slices (pause/resume) with Python steps in-between.")
    parser.add_argument(
        "--slice-ms",
        type=int,
        default=250,
        help="Milliseconds to let the process run per slice (default: 250)",
    )
    parser.add_argument(
        "--slices",
        type=int,
        default=5,
        help="Number of slices to run before letting it finish (default: 5)",
    )
    parser.add_argument(
        "--between",
        action="append",
        default=["pwd", "listdir"],
        help="Python step to run between slices (repeatable). Options: pwd,listdir,uname,env,sleep",
    )
    parser.add_argument("--cwd", default=".", help="Working directory for the ELF (default: .)")
    parser.add_argument("--final", choices=["wait", "terminate"], default="wait", help="What to do after slices")
    parser.add_argument("elf", help="Path to an ELF binary")

    raw_argv = list(argv if argv is not None else sys.argv[1:])
    elf_args: list[str] = []
    if "--" in raw_argv:
        idx = raw_argv.index("--")
        elf_args = raw_argv[idx + 1 :]
        raw_argv = raw_argv[:idx]
    args = parser.parse_args(raw_argv)

    elf_path = Path(args.elf).expanduser().resolve()
    cwd = Path(args.cwd).expanduser().resolve()

    if not elf_path.exists():
        print(f"ELF not found: {elf_path}", file=sys.stderr)
        return 2
    if not _is_elf(elf_path):
        print(f"Not an ELF file: {elf_path}", file=sys.stderr)
        return 2
    if not os.access(elf_path, os.X_OK):
        print(f"ELF is not executable (chmod +x): {elf_path}", file=sys.stderr)
        return 2
    if not cwd.exists() or not cwd.is_dir():
        print(f"Invalid --cwd: {cwd}", file=sys.stderr)
        return 2

    cmd = [str(elf_path)] + elf_args
    print(f"[*] exec: {' '.join(cmd)}")
    print(f"[*] cwd:  {cwd}")

    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd),
        start_new_session=True,  # ensures its own process group
    )

    # Pause immediately (best-effort). This avoids blocking Popen() like a
    # preexec SIGSTOP would.
    try:
        proc.send_signal(signal.SIGSTOP)
    except Exception:
        pass
    _wait_stopped(proc.pid, timeout_s=1.0)

    try:
        slice_s = max(1, args.slice_ms) / 1000.0
        # Run the between-steps once up-front while the process is paused.
        for step in args.between:
            _print_between_step(step, cwd=cwd)

        for i in range(max(0, args.slices)):
            if proc.poll() is not None:
                break

            print(f"[*] slice {i + 1}/{args.slices}: running for {args.slice_ms}ms")
            _killpg(proc.pid, signal.SIGCONT)

            deadline = time.time() + slice_s
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                time.sleep(0.01)

            if proc.poll() is None:
                _killpg(proc.pid, signal.SIGSTOP)
                _wait_stopped(proc.pid, timeout_s=1.0)

            for step in args.between:
                _print_between_step(step, cwd=cwd)

        if proc.poll() is None:
            if args.final == "terminate":
                print("[*] terminating process group")
                _killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    _killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            else:
                print("[*] letting process finish")
                _killpg(proc.pid, signal.SIGCONT)
                proc.wait()

        return int(proc.returncode or 0)
    except KeyboardInterrupt:
        print("\n[!] Ctrl-C: terminating process group", file=sys.stderr)
        _killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            _killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        return 130


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        # stdout pipe closed by consumer; exit cleanly.
        raise SystemExit(0)
