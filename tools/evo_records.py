"""Byte builders for ACOS5-EVO card setup (no card access here).

Record layouts are taken from the carblue/acos5 initialization script (ACOS5-64)
and adjusted for the EVO where its layout differs (tested with a real ACOS5-EVO card).
"""


class SecretNote(str):
    """Step note of a step whose APDU carries key material or a PIN: it is sent but logged without data."""


def tlv(tag: int, value: bytes) -> bytes:
    """Short-form BER-TLV (value shorter than 128 bytes)."""
    if len(value) >= 0x80:
        raise ValueError("value too long for short-form TLV")
    return bytes([tag, len(value)]) + value


def apdu(header: str, data: bytes = b"", le: int | None = None) -> bytes:
    """Build a short APDU from a hex header ('CLA INS P1 P2'), optional data and Le."""
    out = bytes.fromhex(header)
    if len(out) != 4:
        raise ValueError("header must be 4 bytes")
    if data:
        out += bytes([len(data)]) + data
    if le is not None:
        out += bytes([le])
    return out


def create_file(fcp: bytes) -> bytes:
    """CREATE FILE with the given FCP template body (tag 62 is added here)."""
    return apdu("00 E0 00 00", tlv(0x62, fcp))


def select(fid: str) -> bytes:
    return apdu("00 A4 00 00", bytes.fromhex(fid))


def activate(fid: str) -> bytes:
    """ACTIVATE FILE (P1=00). Not to be confused with Activate Card (P1=01)."""
    return apdu("00 44 00 00", bytes.fromhex(fid))


def update_record(rec_no: int, data: bytes) -> bytes:
    return apdu(f"00 DC {rec_no:02X} 04", data)


def update_binary(data: bytes, offset: int = 0) -> bytes:
    return apdu(f"00 D6 {offset >> 8:02X} {offset & 0xFF:02X}", data)


def pin_record(pin: bytes, puk: bytes, retries: int = 8) -> bytes:
    """PIN file record: C1 = valid | resetting code present | PIN id 1.

    Retry byte: high nibble = allowed retries, low nibble = retries left.
    """
    r = (retries << 4) | retries
    return bytes([0xC1, r, len(pin)]) + pin + bytes([r, len(puk)]) + puk


def sym_key_record(key_id: int, key: bytes, algo: int = 0x24, err_counter: int = 0xFF) -> bytes:
    """EVO symmetric key record: [0x80|id] 03 FF FF [error counter] [algo] [key].

    algo: 22 = AES-128, 24 = AES-192, 28 = AES-256, 14 = 3DES-168.
    """
    sizes = {0x22: 16, 0x24: 24, 0x28: 32, 0x14: 24}
    if sizes.get(algo) != len(key):
        raise ValueError("key length does not match algorithm")
    return bytes([0x80 | key_id, 0x03, 0xFF, 0xFF, err_counter, algo]) + key


def se_record(rec_id: int, *crts: bytes) -> bytes:
    """Security environment record: 80 01 <id> followed by control reference templates."""
    return tlv(0x80, bytes([rec_id])) + b"".join(crts)


def at_pin(pin_ref: int) -> bytes:
    """Authentication template: PIN verification of pin_ref (0x01 global, 0x81 local)."""
    return tlv(0xA4, tlv(0x83, bytes([pin_ref])) + tlv(0x95, b"\x08"))


def cct_aes(key_ref: int) -> bytes:
    """Cryptographic checksum template for SM, AES CMAC (EVO algo 1D)."""
    return tlv(0xB4, tlv(0x83, bytes([key_ref])) + tlv(0x95, b"\x30") + tlv(0x80, b"\x1D"))


def ct_aes(key_ref: int) -> bytes:
    """Confidentiality template for SM, AES CBC (EVO algo 15)."""
    return tlv(0xB8, tlv(0x83, bytes([key_ref])) + tlv(0x95, b"\x30") + tlv(0x80, b"\x15"))
