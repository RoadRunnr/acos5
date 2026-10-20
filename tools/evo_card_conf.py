"""Per-card OpenSC configuration sub-block ~/.config/acos5evo/<SERIAL>.conf (no card access here).

Content, for example:
    card 0011223344556677 {
        mode = acl;
        keyset_<AID>_02_enc = "<hex of key 0x82, SM>";
        keyset_<AID>_02_mac = "<hex of key 0x81, host authentication>";
    }
The file holds secret keys: mode 600.
"""
import os
import re

from evo_layout import AID

CONF_DIR = os.path.expanduser("~/.config/acos5evo")
_KEYSET = f"keyset_{AID.hex().upper()}_02"


def default_path(serial: bytes) -> str:
    return os.path.join(CONF_DIR, serial.hex().upper() + ".conf")


def write_card_conf(serial: bytes, *, keys: tuple[bytes, bytes] | None, mode: str = "acl",
                    path: str | None = None) -> str:
    """Write the sub-block; keys = (key81_auth, key82_sm) or None for a block without keysets."""
    path = path or default_path(serial)
    lines = [f"card {serial.hex().upper()} {{", f"    mode = {mode};"]
    if keys is not None:
        auth, sm = keys
        lines += [f'    {_KEYSET}_enc = "{sm.hex().upper()}";', f'    {_KEYSET}_mac = "{auth.hex().upper()}";']
    lines.append("}")
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, ("\n".join(lines) + "\n").encode())
    finally:
        os.close(fd)
    return path


def read_card_keys(serial: bytes, path: str | None = None) -> tuple[bytes, bytes] | None:
    """Return (key81_auth, key82_sm) from the card's file, or None if file or keysets are missing."""
    try:
        with open(path or default_path(serial)) as f:
            text = f.read()
    except FileNotFoundError:
        return None
    found = {}
    for suffix in ("enc", "mac"):
        m = re.search(rf'{_KEYSET}_{suffix}\s*=\s*"([0-9A-Fa-f]{{48}})"', text)
        if not m:
            return None
        found[suffix] = bytes.fromhex(m.group(1))
    return found["mac"], found["enc"]
