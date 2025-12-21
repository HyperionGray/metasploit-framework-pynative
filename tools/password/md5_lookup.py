#!/usr/bin/env python3
"""
Look up MD5 hashes against md5cracker.org-supported backends.

Python port of the Ruby utility. Reads hashes from a file (one per line) and
queries configured databases until a match is found.
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable, List, Tuple

import requests

DATABASES = {
    "all": None,
    "authsecu": "authsecu",
    "i337": "i337.net",
    "md5_my_addr": "md5.my-addr.com",
    "md5_net": "md5.net",
    "md5crack": "md5crack",
    "md5cracker": "md5cracker.org",
    "md5decryption": "md5decryption.com",
    "md5online": "md5online.net",
    "md5pass": "md5pass",
    "netmd5crack": "netmd5crack",
    "tmto": "tmto",
}

DEFAULT_OUTFILE = "md5_results.txt"
LOOKUP_ENDPOINTS = [
    "https://md5cracker.org/api/api.cracker.php",
    "http://md5cracker.org/api/api.cracker.php",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Look up MD5 hashes via md5cracker.org")
    parser.add_argument("-i", "--input", required=True, help="File containing MD5 hashes (one per line)")
    parser.add_argument(
        "-d",
        "--databases",
        default="all",
        help=f"Comma-separated database names ({', '.join(DATABASES.keys())}); default=all",
    )
    parser.add_argument(
        "-o",
        "--out",
        default=DEFAULT_OUTFILE,
        help=f"Optional output file (default {DEFAULT_OUTFILE})",
    )
    parser.add_argument(
        "--assume-yes",
        action="store_true",
        help="Do not prompt before sending hashes to external services",
    )
    return parser.parse_args()


def parse_databases(raw: str) -> List[str]:
    raw_entries = [entry.strip() for entry in raw.split(",") if entry.strip()]
    if not raw_entries or "all" in (entry.lower() for entry in raw_entries):
        return [db for db in DATABASES.values() if db]
    selected = []
    for entry in raw_entries:
        key = entry.lower()
        if key in DATABASES and DATABASES[key]:
            selected.append(DATABASES[key])
    return selected


def confirm_network_opt_in(assume_yes: bool) -> None:
    """Warn the user hashes are sent in cleartext."""
    if assume_yes:
        return
    print("WARNING: Hashes will be sent in cleartext HTTP requests to third-party services.")
    print("This may expose sensitive data.")
    reply = input("[*] Enter 'Y' to acknowledge and continue: ").strip().lower()
    if reply not in ("y", "yes"):
        sys.exit(1)


def iter_hashes(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            value = line.strip()
            if len(value) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in value):
                yield value
            elif value:
                sys.stderr.write(f"[-] Skipping invalid MD5 entry: {value}\n")


def lookup_hash(hash_value: str, database: str, session: requests.Session) -> Tuple[str, str]:
    params = {"database": database, "hash": hash_value}
    for endpoint in LOOKUP_ENDPOINTS:
        try:
            resp = session.get(endpoint, params=params, timeout=15)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except ValueError:
            continue
        if data.get("status"):
            return data.get("result", ""), endpoint
        return "", endpoint
    return "", ""


def main() -> None:
    args = parse_args()
    dbs = parse_databases(args.databases)
    if not dbs:
        sys.stderr.write("[-] No valid databases selected\n")
        sys.exit(1)

    confirm_network_opt_in(args.assume_yes)

    hashes = list(iter_hashes(args.input))
    if not hashes:
        sys.stderr.write("[-] No valid MD5 hashes loaded\n")
        sys.exit(1)

    output_handle = None
    try:
        output_handle = open(args.out, "w", encoding="utf-8")
    except OSError:
        sys.stderr.write(f"[-] Unable to open {args.out} for writing; results will not be saved\n")
        output_handle = None

    session = requests.Session()
    for hash_value in hashes:
        for db in dbs:
            cracked, endpoint = lookup_hash(hash_value, db, session)
            if cracked:
                message = f"[*] Found: {hash_value} = {cracked} (from {db})"
                print(message)
                if output_handle:
                    output_handle.write(f"{hash_value} = {cracked}\n")
                break
            if endpoint:
                # One request was made; no need to hammer multiple endpoints if a DB fails.
                continue

    if output_handle:
        output_handle.close()


if __name__ == "__main__":
    main()
