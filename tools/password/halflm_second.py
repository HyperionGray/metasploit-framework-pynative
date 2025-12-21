#!/usr/bin/env python3
"""
Half-LM challenge/response helper (Python port)

Given the first 7 characters of an LM password and an LM challenge/response
pair that used a static challenge, brute-force the remaining characters.
"""

from __future__ import annotations

import argparse
import itertools
import sys
import time
from typing import Iterable, List, Optional

from ntlm_utils import lm_hash, lm_response

DEFAULT_CHALLENGE = "1122334455667788"


def build_charset() -> List[int]:
    """Replicate the Ruby charset generation (uppercased bytes 0x01-0xFF, unique)."""
    values: List[int] = []
    seen = set()
    for byte in range(1, 256):
        upper = ord(chr(byte).upper())
        if upper not in seen:
            seen.add(upper)
            values.append(upper)
    return values


def compute_response_hex(password: str, challenge: bytes) -> str:
    """Compute LM response hex for a candidate password."""
    return lm_response(lm_hash(password), challenge).hex()


def brute_suffix(
    prefix: str, charset: Iterable[int], challenge: bytes, target_hash: str, length: int
) -> Optional[str]:
    """Brute-force a suffix of given length."""
    for combo in itertools.product(charset, repeat=length):
        candidate = prefix + "".join(chr(c) for c in combo)
        if compute_response_hex(candidate, challenge) == target_hash:
            return candidate
    return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crack an LM challenge/response when the first 7 characters are known."
    )
    parser.add_argument("-n", "--hash", required=True, help="Encrypted LM response (48 hex characters)")
    parser.add_argument("-p", "--password", required=True, help="Known first 7 characters of the LM password")
    parser.add_argument(
        "-s",
        "--challenge",
        default=DEFAULT_CHALLENGE,
        help=f"Server challenge hex (default {DEFAULT_CHALLENGE})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    lm_hash_hex = args.hash.strip().lower()
    known_prefix = args.password.strip().upper()
    challenge_hex = args.challenge.strip()

    if len(lm_hash_hex) != 48 or not all(ch in "0123456789abcdef" for ch in lm_hash_hex.lower()):
        sys.stderr.write("[*] LANMAN should be exactly 48 bytes of hexadecimal\n")
        sys.exit(1)
    if len(known_prefix) != 7:
        sys.stderr.write("[*] Cracked LANMAN password should be exactly 7 characters\n")
        sys.exit(1)
    if len(challenge_hex) != 16 or any(ch not in "0123456789abcdef" for ch in challenge_hex.lower()):
        sys.stderr.write("[*] Server challenge must be exactly 16 bytes of hexadecimal\n")
        sys.exit(1)

    target_response = lm_hash_hex
    challenge = bytes.fromhex(challenge_hex)
    charset = build_charset()

    def try_length(length: int) -> Optional[str]:
        start = time.time()
        result = brute_suffix(known_prefix, charset, challenge, target_response, length)
        elapsed = time.time() - start
        if result:
            return result
        if length < 4:
            eta = elapsed * (len(charset) ** (length + 1))
            print(f"[*] Trying {length + 1} characters (eta: {int(eta)} seconds)...")
        return None

    print("[*] Trying one character...")
    for size in range(1, 5):
        found = try_length(size)
        if found:
            print(f"[*] Cracked: {found}")
            return

    print("[*] No match found up to 4 unknown characters.")


if __name__ == "__main__":
    main()
