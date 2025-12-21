#!/usr/bin/env python3
"""
Crack LM/NTLM challenge-response hashes (Python port of lm2ntcrack.rb).

Supports HALFLM, LM, NTLM, HALFNETLMv1, NETLMv1, NETNTLMv1, NETNTLM2_SESSION,
NETLMv2, and NETNTLMv2 modes. Depending on inputs it can print hashes, verify
passwords, or brute-force using a wordlist.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Iterable, List

from ntlm_utils import (
    lm_hash,
    lm_response,
    lmv2_response,
    ntlm_hash,
    ntlm_response,
    ntlm2_session_response,
    ntlmv2_hash,
    ntlmv2_response,
)


BRUTE_MODE = "brute"
HASH_MODE = "hash"
PASS_MODE = "pass"


def permute_pw(password: str) -> List[str]:
    """Generate uppercase/lowercase permutations (fast version of Ruby helper)."""
    perms = [""]
    tail = password.lower()
    while tail:
        head, tail = tail[0], tail[1:]
        head_upper = head.upper()
        current = list(perms)
        for i, prefix in enumerate(current):
            perms[i] = prefix + head_upper
            if head_upper != head:
                perms.append(prefix + head)
    return perms


def validate_hex(value: str, length: int, label: str) -> bytes:
    if not value or len(value) != length or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise ValueError(f"{label} must be exactly {length} bytes of hexadecimal")
    return bytes.fromhex(value)


def validate_hex_min(value: str, min_length: int, label: str) -> bytes:
    if not value or len(value) < min_length or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise ValueError(f"{label} must be at least {min_length} hexadecimal characters")
    if len(value) % 2:
        raise ValueError(f"{label} must contain an even number of hexadecimal characters")
    return bytes.fromhex(value)


def load_wordlist(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def lm_hash_hex(password: str, half: bool = False) -> str:
    return lm_hash(password, half=half).hex().upper()


def ntlm_hash_hex(password: str) -> str:
    return ntlm_hash(password).hex().upper()


def lm_response_hex(lm_hash_bytes: bytes, challenge: bytes, half: bool = False) -> str:
    return lm_response(lm_hash_bytes, challenge, half=half).hex().upper()


def ntlm_response_hex(ntlm_hash_bytes: bytes, challenge: bytes) -> str:
    return ntlm_response(ntlm_hash_bytes, challenge).hex().upper()


def ntlm2_session_hex(ntlm_hash_bytes: bytes, challenge: bytes, client_challenge: bytes) -> str:
    return ntlm2_session_response(ntlm_hash_bytes, challenge, client_challenge).hex().upper()


def lmv2_response_hex(ntlmv2_key: bytes, challenge: bytes, client_challenge: bytes) -> str:
    return lmv2_response(ntlmv2_key, challenge, client_challenge).hex().upper()


def ntlmv2_response_hex(ntlmv2_key: bytes, challenge: bytes, client_blob: bytes) -> str:
    return ntlmv2_response(ntlmv2_key, challenge, client_blob).hex().upper()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Crack LM/NTLM hashes (Python port of lm2ntcrack.rb)"
    )
    parser.add_argument(
        "-t",
        "--type",
        required=True,
        help="HALFLM/LM/NTLM/HALFNETLMv1/NETLMv1/NETNTLMv1/NETNTLM2_SESSION/NETLMv2/NETNTLMv2",
    )
    parser.add_argument("-a", "--hash", help="Hash to crack/verify")
    parser.add_argument("-p", "--password", help="Password to hash or verify")
    parser.add_argument("-l", "--list", help="Password list for bruteforce mode")
    parser.add_argument("-s", "--server-challenge", help="LM/NTLM server challenge (hex)")
    parser.add_argument("-c", "--client-challenge", help="LM/NTLM client challenge (hex)")
    parser.add_argument("-u", "--user", help="Username (for NTLMv2/LMv2)")
    parser.add_argument("-d", "--domain", help="Domain (for NTLMv2/LMv2)")
    return parser.parse_args()


def determine_mode(args: argparse.Namespace) -> str:
    if args.password and not (args.hash or args.list):
        return HASH_MODE
    if args.password and args.hash and not args.list:
        return PASS_MODE
    if args.list and args.hash and not args.password:
        if not os.path.isfile(args.list) or not os.access(args.list, os.R_OK):
            raise ValueError("The passwords list file must exist and be readable")
        return BRUTE_MODE
    raise ValueError("Usage: requires -t type with appropriate -a/-p/-l combination")


def handle_halflm(mode: str, args: argparse.Namespace) -> None:
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 16, "HALFLM HASH")
        for password in load_wordlist(args.list):
            if 1 <= len(password) <= 7:
                print(password)
                calc = lm_hash_hex(password.upper(), half=True)
                if calc == target:
                    print(f"[*] Correct password found : {password.upper()}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        if not args.password or len(args.password) > 7:
            raise ValueError("LM password can not be bigger than 7 characters")
        calc = lm_hash_hex(args.password.upper(), half=True)
        print(f"[*] The LM hash for {args.password.upper()} is : {calc}")
    else:  # PASS_MODE
        if not args.password or len(args.password) > 7:
            raise ValueError("LM password can not be bigger than 7 characters")
        validate_hex(args.hash, 16, "HALFLM HASH")
        calc = lm_hash_hex(args.password.upper(), half=True)
        if args.hash.upper() == calc:
            print(f"[*] Correct password provided : {args.password.upper()}")
        else:
            print(f"[*] Incorrect password provided : {args.password.upper()}")


def handle_lm(mode: str, args: argparse.Namespace) -> None:
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 32, "LM HASH")
        for password in load_wordlist(args.list):
            if 1 <= len(password) <= 14:
                print(password)
                calc = lm_hash_hex(password.upper())
                if calc == target:
                    print(f"[*] Correct password found : {password.upper()}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        if not args.password or len(args.password) > 14:
            raise ValueError("LM password can not be bigger than 14 characters")
        calc = lm_hash_hex(args.password.upper())
        print(f"[*] The LM hash for {args.password.upper()} is : {calc}")
    else:
        if not args.password or len(args.password) > 14:
            raise ValueError("LM password can not be bigger than 14 characters")
        validate_hex(args.hash, 32, "LM HASH")
        calc = lm_hash_hex(args.password.upper())
        if args.hash.upper() == calc:
            print(f"[*] Correct password provided : {args.password.upper()}")
        else:
            print(f"[*] Incorrect password provided : {args.password.upper()}")


def handle_ntlm(mode: str, args: argparse.Namespace) -> None:
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 32, "NTLM HASH")
        for password in load_wordlist(args.list):
            for permuted in permute_pw(password):
                print(permuted)
                if ntlm_hash_hex(permuted) == target:
                    print(f"[*] Correct password found : {permuted}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        calc = ntlm_hash_hex(args.password)
        print(f"[*] The NTLM hash for {args.password} is : {calc}")
    else:
        validate_hex(args.hash, 32, "NTLM HASH")
        for permuted in permute_pw(args.password):
            if ntlm_hash_hex(permuted) == args.hash.upper():
                print(f"[*] Correct password provided : {permuted}")
                sys.exit(0)
        print(f"[*] Incorrect password provided : {args.password}")


def handle_halfnetlmv1(mode: str, args: argparse.Namespace) -> None:
    srv_chal = validate_hex(args.server_challenge or "", 16, "Server challenge")
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 16, "HALFNETLMv1 HASH")
        for password in load_wordlist(args.list):
            if 1 <= len(password) <= 7:
                print(password)
                lm_partial = lm_hash(password, half=True)[:7]
                calc = lm_response_hex(lm_partial, srv_chal, half=True)
                if calc == target:
                    print(f"[*] Correct password found : {password.upper()}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        if not args.password or len(args.password) > 7:
            raise ValueError("HALFNETLMv1 password can not be bigger than 7 characters")
        lm_partial = lm_hash(args.password, half=True)[:7]
        calc = lm_response_hex(lm_partial, srv_chal, half=True)
        print(f"[*] The HALFNETLMv1 hash for {args.password.upper()} is : {calc}")
    else:
        if not args.password or len(args.password) > 7:
            raise ValueError("HALFNETLMv1 password can not be bigger than 7 characters")
        validate_hex(args.hash, 16, "HALFNETLMv1 HASH")
        lm_partial = lm_hash(args.password, half=True)[:7]
        calc = lm_response_hex(lm_partial, srv_chal, half=True)
        if args.hash.upper() == calc:
            print(f"[*] Correct password provided : {args.password.upper()}")
        else:
            print(f"[*] Incorrect password provided : {args.password.upper()}")


def handle_netlmv1(mode: str, args: argparse.Namespace) -> None:
    srv_chal = validate_hex(args.server_challenge or "", 16, "Server challenge")
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 48, "NETLMv1 HASH")
        for password in load_wordlist(args.list):
            if 1 <= len(password) <= 14:
                print(password)
                calc = lm_response_hex(lm_hash(password), srv_chal)
                if calc == target:
                    print(f"[*] Correct password found : {password.upper()}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        if not args.password or len(args.password) > 14:
            raise ValueError("NETLMv1 password can not be bigger than 14 characters")
        calc = lm_response_hex(lm_hash(args.password), srv_chal)
        print(f"[*] The NETLMv1 hash for {args.password.upper()} is : {calc}")
    else:
        if not args.password or len(args.password) > 14:
            raise ValueError("NETLMv1 password can not be bigger than 14 characters")
        validate_hex(args.hash, 48, "NETLMv1 HASH")
        calc = lm_response_hex(lm_hash(args.password), srv_chal)
        if args.hash.upper() == calc:
            print(f"[*] Correct password provided : {args.password.upper()}")
        else:
            print(f"[*] Incorrect password provided : {args.password.upper()}")


def handle_netntlmv1(mode: str, args: argparse.Namespace) -> None:
    srv_chal = validate_hex(args.server_challenge or "", 16, "Server challenge")
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 48, "NETNTLMv1 HASH")
        for password in load_wordlist(args.list):
            for permuted in permute_pw(password):
                print(permuted)
                calc = ntlm_response_hex(ntlm_hash(permuted), srv_chal)
                if calc == target:
                    print(f"[*] Correct password found : {permuted}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        calc = ntlm_response_hex(ntlm_hash(args.password), srv_chal)
        print(f"[*] The NETNTLMv1 hash for {args.password} is : {calc}")
    else:
        validate_hex(args.hash, 48, "NETNTLMv1 HASH")
        for permuted in permute_pw(args.password):
            calc = ntlm_response_hex(ntlm_hash(permuted), srv_chal)
            if args.hash.upper() == calc:
                print(f"[*] Correct password provided : {permuted}")
                sys.exit(0)
        print(f"[*] Incorrect password provided : {args.password}")


def handle_netntlm2_session(mode: str, args: argparse.Namespace) -> None:
    srv_chal = validate_hex(args.server_challenge or "", 16, "Server challenge")
    cli_chal = validate_hex(args.client_challenge or "", 16, "Client challenge")
    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 48, "NETNTLM2_SESSION HASH")
        for password in load_wordlist(args.list):
            for permuted in permute_pw(password):
                print(permuted)
                calc = ntlm2_session_hex(ntlm_hash(permuted), srv_chal, cli_chal)
                if calc == target:
                    print(f"[*] Correct password found : {permuted}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        calc = ntlm2_session_hex(ntlm_hash(args.password), srv_chal, cli_chal)
        print(f"[*] The NETNTLM2_SESSION hash for {args.password} is : {calc}")
    else:
        validate_hex(args.hash, 48, "NETNTLM2_SESSION HASH")
        for permuted in permute_pw(args.password):
            calc = ntlm2_session_hex(ntlm_hash(permuted), srv_chal, cli_chal)
            if args.hash.upper() == calc:
                print(f"[*] Correct password provided : {permuted}")
                sys.exit(0)
        print(f"[*] Incorrect password provided : {args.password}")


def handle_netlmv2(mode: str, args: argparse.Namespace) -> None:
    srv_chal = validate_hex(args.server_challenge or "", 16, "Server challenge")
    cli_chal = validate_hex(args.client_challenge or "", 16, "Client challenge")
    if not args.user or not args.domain:
        raise ValueError("User name and domain must be provided with this type")

    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 32, "NETLMv2 HASH")
        for password in load_wordlist(args.list):
            print(password)
            key = ntlmv2_hash(args.user, password, args.domain)
            calc = lmv2_response_hex(key, srv_chal, cli_chal)[:32]
            if calc == target:
                print(f"[*] Correct password found : {password}")
                sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        key = ntlmv2_hash(args.user, args.password, args.domain)
        calc = lmv2_response_hex(key, srv_chal, cli_chal)[:32]
        print(f"[*] The NETLMv2 hash for {args.password} is : {calc}")
    else:
        validate_hex(args.hash, 32, "NETLMv2 HASH")
        key = ntlmv2_hash(args.user, args.password, args.domain)
        calc = lmv2_response_hex(key, srv_chal, cli_chal)[:32]
        if args.hash.upper() == calc:
            print(f"[*] Correct password provided : {args.password}")
        else:
            print(f"[*] Incorrect password provided : {args.password}")


def handle_netntlmv2(mode: str, args: argparse.Namespace) -> None:
    srv_chal = validate_hex(args.server_challenge or "", 16, "Server challenge")
    cli_blob = validate_hex_min(args.client_challenge or "", 17, "Client challenge")
    if not args.user or not args.domain:
        raise ValueError("User name and domain must be provided with this type")

    if mode == BRUTE_MODE:
        target = args.hash.upper()
        validate_hex(args.hash, 32, "NETNTLMv2 HASH")
        for password in load_wordlist(args.list):
            for permuted in permute_pw(password):
                print(permuted)
                key = ntlmv2_hash(args.user, permuted, args.domain)
                calc = ntlmv2_response_hex(key, srv_chal, cli_blob)[:32]
                if calc == target:
                    print(f"[*] Correct password found : {password}")
                    sys.exit(0)
        print("[*] No password found")
    elif mode == HASH_MODE:
        key = ntlmv2_hash(args.user, args.password, args.domain)
        calc = ntlmv2_response_hex(key, srv_chal, cli_blob)[:32]
        print(f"[*] The NETNTLMv2 hash for {args.password} is : {calc}")
    else:
        validate_hex(args.hash, 32, "NETNTLMv2 HASH")
        for permuted in permute_pw(args.password):
            key = ntlmv2_hash(args.user, permuted, args.domain)
            calc = ntlmv2_response_hex(key, srv_chal, cli_blob)[:32]
            if args.hash.upper() == calc:
                print(f"[*] Correct password provided : {permuted}")
                sys.exit(0)
        print(f"[*] Incorrect password provided : {args.password}")


def main() -> None:
    args = parse_args()
    args.type = args.type.upper()
    try:
        mode = determine_mode(args)
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        sys.exit(1)

    handlers = {
        "HALFLM": handle_halflm,
        "LM": handle_lm,
        "NTLM": handle_ntlm,
        "HALFNETLMV1": handle_halfnetlmv1,
        "NETLMV1": handle_netlmv1,
        "NETNTLMV1": handle_netntlmv1,
        "NETNTLM2_SESSION": handle_netntlm2_session,
        "NETLMV2": handle_netlmv2,
        "NETNTLMV2": handle_netntlmv2,
    }

    handler = handlers.get(args.type)
    if not handler:
        sys.stderr.write(
            "type must be of type : HALFLM/LM/NTLM/HALFNETLMv1/NETLMv1/NETNTLMv1/NETNTLM2_SESSION/NETLMv2/NETNTLMv2\n"
        )
        sys.exit(1)

    try:
        handler(mode, args)
    except ValueError as exc:
        sys.stderr.write(f"[*] {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
