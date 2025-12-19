#!/usr/bin/env python3
"""
Bruteforce HMAC-SHA1 hashes with binary salts.

Python port of the original Ruby tool, aimed at cracking IPMI 2.0 style
hashes that embed large/binary salts.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import sys
import time
from dataclasses import dataclass, field
from typing import List


@dataclass
class HashEntry:
    identifier: str
    salt: bytes
    digest: bytes
    cracked: bool = field(default=False)


def parse_hash_file(path: str) -> List[HashEntry]:
    entries: List[HashEntry] = []
    with open(path, "rb") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                parts = line.decode(errors="replace").strip().split(":", 2)
            except Exception:
                sys.stderr.write(f"[-] Unable to parse line (encoding issue): {line!r}\n")
                continue
            if len(parts) != 3:
                sys.stderr.write(f"[-] Invalid hash entry, missing field: {line.decode(errors='replace')}\n")
                continue
            ident, salt_hex, hash_hex = parts
            try:
                salt = bytes.fromhex(salt_hex)
            except ValueError:
                sys.stderr.write(f"[-] Invalid hash entry, salt must be hex: {salt_hex}\n")
                continue
            try:
                digest = bytes.fromhex(hash_hex)
            except ValueError:
                sys.stderr.write(f"[-] Invalid hash entry, digest must be hex: {hash_hex}\n")
                continue
            entries.append(HashEntry(ident, salt, digest))
    return entries


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crack HMAC-SHA1 hashes (e.g. IPMI 2.0) with binary salts."
    )
    parser.add_argument("hash_file", help="File containing hashes in the form <id>:<hex-salt>:<hex-digest>")
    parser.add_argument(
        "wordlist",
        help="Wordlist to try, or '-' to read from stdin",
    )
    return parser.parse_args()


def format_password(password: bytes) -> str:
    """Display password bytes safely."""
    try:
        return password.decode()
    except UnicodeDecodeError:
        return password.decode("utf-8", errors="backslashreplace")


def main() -> None:
    args = parse_args()
    hashes = parse_hash_file(args.hash_file)
    if not hashes:
        sys.stderr.write("[-] No valid hashes loaded; exiting\n")
        sys.exit(1)

    word_fd = sys.stdin.buffer if args.wordlist == "-" else open(args.wordlist, "rb")

    start = time.time()
    attempts = 0
    cracked = 0

    try:
        for raw_word in word_fd:
            password = raw_word.rstrip(b"\r\n")
            for entry in hashes:
                if hmac.new(password, entry.salt, hashlib.sha1).digest() == entry.digest:
                    print(
                        f"{entry.identifier}:{entry.salt.hex()}:{entry.digest.hex()}:{format_password(password)}"
                    )
                    entry.cracked = True
                    cracked += 1
                attempts += 1
                if attempts % 2_500_000 == 0:
                    rate = int(attempts / max(time.time() - start, 0.001))
                    sys.stderr.write(
                        f"[*] Found {cracked} passwords with {len(hashes)} left ({rate}/s)\n"
                    )
            hashes = [h for h in hashes if not h.cracked]
            if not hashes:
                break
    finally:
        if word_fd is not sys.stdin.buffer:
            word_fd.close()

    rate = int(attempts / max(time.time() - start, 0.001))
    sys.stderr.write(f"[*] Cracked {cracked} passwords with {len(hashes)} left ({rate}/s)\n")


if __name__ == "__main__":
    main()
