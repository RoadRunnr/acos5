"""Derive the ACOS5-EVO card keys from the master key kmc and the card serial.

NIST SP 800-108 counter mode with AES-CMAC as PRF. kmc is 32 bytes (AES-256).
Each block is CMAC(kmc, [i] || label || 00 || context || L), i a 1-byte counter
starting at 1, L the output length in bits (2 bytes, big-endian).
"""
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

LABEL_SM = b"ACOS5-EVO SM"      # key 82
LABEL_AUTH = b"ACOS5-EVO AUTH"  # key 81
KEY_LEN = 24                    # AES-192


def kbkdf_cmac(kmc: bytes, label: bytes, context: bytes, out_len: int) -> bytes:
    fixed = label + b"\x00" + context + (out_len * 8).to_bytes(2, "big")
    out = b""
    i = 1
    while len(out) < out_len:
        c = CMAC(algorithms.AES(kmc))
        c.update(bytes([i]) + fixed)
        out += c.finalize()
        i += 1
    return out[:out_len]


def derive_card_keys(kmc: bytes, serial: bytes) -> tuple[bytes, bytes]:
    """Return (key81_auth, key82_sm), 24 bytes each."""
    if len(kmc) != 32:
        raise ValueError("kmc must be 32 bytes")
    if len(serial) != 8:
        raise ValueError("serial must be 8 bytes")
    return (kbkdf_cmac(kmc, LABEL_AUTH, serial, KEY_LEN),
            kbkdf_cmac(kmc, LABEL_SM, serial, KEY_LEN))
