#!/usr/bin/env python3
"""
NTLM/LANMAN hashing helpers used by password utilities.

These helpers mirror the behavior of the original Ruby Rex::Proto::NTLM::Crypt
utilities but rely on pycryptodome primitives for DES and MD4.
"""

from __future__ import annotations

import hmac
import struct
from typing import Iterable, List

from Crypto.Cipher import DES
from Crypto.Hash import MD4
from Crypto.Hash import MD5


LM_MAGIC = b"KGS!@#$%"


def _des_56_to_64(key56: bytes) -> bytes:
    """Expand a 56-bit key (7 bytes) to a 64-bit DES key without parity."""
    k = list(key56)
    key64 = [
        k[0],
        ((k[0] << 7) & 0xFF) | (k[1] >> 1),
        ((k[1] << 6) & 0xFF) | (k[2] >> 2),
        ((k[2] << 5) & 0xFF) | (k[3] >> 3),
        ((k[3] << 4) & 0xFF) | (k[4] >> 4),
        ((k[4] << 3) & 0xFF) | (k[5] >> 5),
        ((k[5] << 2) & 0xFF) | (k[6] >> 6),
        (k[6] << 1) & 0xFF,
    ]
    return bytes(key64)


def _gen_keys(key_material: bytes) -> List[bytes]:
    """Split key material into 7-byte chunks and convert to DES keys."""
    return [_des_56_to_64(key_material[i : i + 7]) for i in range(0, len(key_material), 7)]


def _apply_des(block: bytes, keys: Iterable[bytes]) -> List[bytes]:
    """Encrypt a block with each DES key and return the results."""
    return [DES.new(key, DES.MODE_ECB).encrypt(block) for key in keys]


def _pack_int64le(value: int) -> bytes:
    """Pack an integer into 8 bytes little endian."""
    return struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)


def lm_hash(password: str, half: bool = False) -> bytes:
    """Compute an LM hash (full or half)."""
    size = 7 if half else 14
    padded = password.upper().encode("latin-1", errors="ignore").ljust(size, b"\x00")
    keys = _gen_keys(padded)
    return b"".join(_apply_des(LM_MAGIC, keys))


def lm_response(lm_hash_bytes: bytes, challenge: bytes, half: bool = False) -> bytes:
    """Generate an LM/half-LM response to an 8-byte challenge."""
    if isinstance(challenge, int):
        challenge = _pack_int64le(challenge)
    if len(challenge) != 8:
        raise ValueError("Challenge must be exactly 8 bytes")

    size = 7 if half else 21
    keys = _gen_keys(lm_hash_bytes.ljust(size, b"\x00"))
    return b"".join(_apply_des(challenge, keys))


def ntlm_hash(password: str) -> bytes:
    """Compute NTLM hash (MD4 of UTF-16LE password)."""
    md4 = MD4.new()
    md4.update(password.encode("utf-16le"))
    return md4.digest()


def ntlm_response(ntlm_hash_bytes: bytes, challenge: bytes) -> bytes:
    """Generate NTLM response to an 8-byte challenge."""
    if isinstance(challenge, int):
        challenge = _pack_int64le(challenge)
    if len(challenge) != 8:
        raise ValueError("Challenge must be exactly 8 bytes")

    keys = _gen_keys(ntlm_hash_bytes.ljust(21, b"\x00"))
    return b"".join(_apply_des(challenge, keys))


def ntlmv2_hash(user: str, password: str | bytes, domain: str, pass_is_hash: bool = False) -> bytes:
    """Compute NTLMv2 hash for a user/domain pair."""
    if pass_is_hash:
        nt_hash = password if isinstance(password, bytes) else bytes.fromhex(password)
    else:
        nt_hash = ntlm_hash(password)

    identity = (user.upper() + domain).encode("utf-16le")
    return hmac.new(nt_hash, identity, digestmod=MD5).digest()


def lmv2_response(ntlmv2_key: bytes, challenge: bytes, client_challenge: bytes) -> bytes:
    """Compute LMv2 response."""
    if isinstance(challenge, int):
        challenge = _pack_int64le(challenge)
    if len(challenge) != 8:
        raise ValueError("Server challenge must be exactly 8 bytes")
    if len(client_challenge) != 8:
        raise ValueError("Client challenge must be exactly 8 bytes")

    mac = hmac.new(ntlmv2_key, challenge + client_challenge, digestmod=MD5).digest()
    return mac + client_challenge


def ntlmv2_response(ntlmv2_key: bytes, challenge: bytes, client_blob: bytes) -> bytes:
    """Compute NTLMv2 response with provided client blob."""
    if isinstance(challenge, int):
        challenge = _pack_int64le(challenge)
    mac = hmac.new(ntlmv2_key, challenge + client_blob, digestmod=MD5).digest()
    return mac + client_blob


def ntlm2_session_response(ntlm_hash_bytes: bytes, challenge: bytes, client_challenge: bytes) -> bytes:
    """Compute NTLM2 session response (24 bytes)."""
    if isinstance(challenge, int):
        challenge = _pack_int64le(challenge)
    if len(challenge) != 8:
        raise ValueError("Server challenge must be exactly 8 bytes")
    if len(client_challenge) != 8:
        raise ValueError("Client challenge must be exactly 8 bytes")

    session_hash = MD5.new(challenge + client_challenge).digest()[:8]
    keys = _gen_keys(ntlm_hash_bytes.ljust(21, b"\x00"))
    return b"".join(_apply_des(session_hash, keys))
