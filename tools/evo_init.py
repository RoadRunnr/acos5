#!/usr/bin/env python3
"""Initialize an ACS ACOS5-EVO card for OpenSC and the acos5_external driver.

Wipes the card (zeroize), then creates the layout from evo_layout.py.
On any unexpected status word the run stops and the card is wiped again.
All APDUs go through safecard.SafeCard, which refuses life-cycle changes,
card activation and writes to the card header block.

Usage:  evo_init.py [--yes] [--wipe-only] [--so-pin P] [--so-puk P] [--user-pin P] [--user-puk P]
                   [--sm | --kmc-file PATH] [--bind]
Refuses cards that are not an ACOS5-EVO. Asks before wiping unless --yes is given.
EVO_READER=<part of the reader name> selects the reader when several are attached.
A PUK defaults to its PIN (as in carblue's script). The OpenSC tools cannot change a PUK later.
Secure messaging is opt-in:
  --sm       put the SM / authentication keys on the card. They come from an existing
             ~/.config/acos5evo/<SERIAL>.conf, else they are generated randomly.
             The file is written with mode 600.
  --kmc-file PATH
             derive the keys from a 32 byte master key, read as 64 hex digits from PATH (implies --sm).
             PATH must not be readable or writable by group or others (mode 600). Only the mode is
             written to <SERIAL>.conf, the keys are not stored.
  --bind     also require SM for VERIFY / CHANGE / RESET RETRY COUNTER and for reading the
             PKCS#15 directory files (needs --sm).
"""
import argparse
import os
import stat
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evo_card_conf  # noqa: E402
import evo_layout  # noqa: E402
from evo_kdf import derive_card_keys  # noqa: E402
from evo_records import SecretNote, apdu  # noqa: E402
from safecard import SafeCard  # noqa: E402

# ACOS5-EVO ATR, revisions 41 05 4X; the last byte (check byte) is ignored
EVO_ATR = bytes.fromhex("3B 9E 96 80 01 41 05 40 00 00 00 00 00 00 00 00 00 90 00")
EVO_ATR_MASK = bytes.fromhex("FF FF FF FF FF FF FF F0 FF FF FF FF FF FF FF FF FF FF FF")


def is_evo(atr: bytes) -> bool:
    return len(atr) == 20 and all(a & m == e for a, m, e in zip(atr, EVO_ATR_MASK, EVO_ATR))


def read_kmc_file(path):
    """The 32 byte master key from a file with 64 hex digits; the file must have no group or other access."""
    with open(path) as f:
        mode = stat.S_IMODE(os.fstat(f.fileno()).st_mode)
        if mode & 0o077:
            raise ValueError(f"{path} has mode {mode:03o}; it must not be accessible by group or others (chmod 600)")
        text = f.read().strip()
    try:
        kmc = bytes.fromhex(text)
    except ValueError:
        raise ValueError(f"{path} must hold the master key as hex") from None
    if len(kmc) != 32:
        raise ValueError(f"{path} must hold 32 bytes (64 hex digits)")
    return kmc


def choose_sm_keys(serial, kmc):
    """Return (key81, key82) for --sm and write <SERIAL>.conf; never prints key values."""
    if kmc is not None:
        keys = derive_card_keys(kmc, serial)
        path = evo_card_conf.write_card_conf(serial, keys=None)
        print(f"keys derived from the master key; not stored; mode written to {path}")
        return keys
    keys = evo_card_conf.read_card_keys(serial)
    if keys is not None:
        print(f"using the keys from {evo_card_conf.default_path(serial)}")
        return keys
    keys = os.urandom(24), os.urandom(24)
    print("generated random keys, stored in", evo_card_conf.write_card_conf(serial, keys=keys))
    return keys


def wipe(card, so_pin):
    _, sw = card.tx("80 30 00 00 00", "zeroize")
    if sw == 0x6982:
        # MF exists and zeroize needs the SO PIN
        card.tx("00 A4 00 00 02 3F 00", "select MF")
        _, sw = card.tx(apdu("00 20 00 01", so_pin), "verify SO PIN", secret=True)
        if sw != 0x9000:
            raise SystemExit(f"SO PIN verification failed: {sw:04X} - not retrying, to protect the retry counter")
        _, sw = card.tx("80 30 00 00 00", "zeroize")
    if sw != 0x9000:
        raise SystemExit(f"zeroize failed: {sw:04X}")
    print("card wiped")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yes", action="store_true", help="wipe without asking")
    ap.add_argument("--wipe-only", action="store_true")
    ap.add_argument("--so-pin", default="87654321")
    ap.add_argument("--so-puk", help="default: the SO PIN")
    ap.add_argument("--user-pin", default="12345678")
    ap.add_argument("--user-puk", help="default: the user PIN")
    ap.add_argument("--sm", action="store_true", help="put the SM keys on the card")
    ap.add_argument("--kmc-file", metavar="PATH",
                    help="derive the SM keys from the 32 byte master key in this file, 64 hex digits, mode 600"
                         " (implies --sm)")
    ap.add_argument("--bind", action="store_true", help="require SM for PIN commands and PKCS#15 reads (needs --sm)")
    args = ap.parse_args()
    kmc = None
    if args.kmc_file is not None:
        args.sm = True
        try:
            kmc = read_kmc_file(args.kmc_file)
        except (OSError, ValueError) as e:
            ap.error(f"--kmc-file: {e}")
    if args.bind and not args.sm:
        ap.error("--bind requires --sm")
    so_pin, user_pin = args.so_pin.encode(), args.user_pin.encode()
    so_puk = (args.so_puk or args.so_pin).encode()
    user_puk = (args.user_puk or args.user_pin).encode()
    if not all(4 <= len(p) <= 8 for p in (so_pin, so_puk, user_pin, user_puk)):
        raise SystemExit("PINs and PUKs must be 4..8 characters")

    card = SafeCard()
    if not is_evo(card.atr()):
        raise SystemExit(f"not an ACOS5-EVO (ATR {card.atr().hex(' ').upper()}); nothing changed")
    serial, sw = card.tx("80 14 00 00 08", "serial")
    if sw != 0x9000:
        raise SystemExit("cannot read serial")
    if not args.yes:
        answer = input(f"Wipe all data on the card {serial.hex().upper()} in {card.reader}? Type yes: ")
        if answer.strip() != "yes":
            raise SystemExit("nothing changed")
    wipe(card, so_pin)
    if args.wipe_only:
        return

    sm = args.sm
    key1, key2 = choose_sm_keys(serial, kmc) if sm else (None, None)
    if sm:
        print("WARNING: if the SM keys are lost, files and keys bound to them become unusable;"
              " ZEROIZE and a new setup is the only recovery.")
    steps = (evo_layout.piece2_mf_and_global_files(so_pin, so_puk)
             + evo_layout.piece3_app_df(user_pin, user_puk, key1, key2, sm=sm, bind=args.bind)
             + evo_layout.piece4_pkcs15(serial, sm=sm, bind=args.bind))
    for i, (cmd, note) in enumerate(steps, 1):
        _, sw = card.tx(cmd, note, secret=isinstance(note, SecretNote))
        if sw != 0x9000 and (sw >> 8) != 0x61:     # 61xx: success, response data available
            print(f"step {i} '{note}' failed with SW={sw:04X}; wiping the card again")
            card.reset()
            wipe(card, so_pin)
            raise SystemExit(1)
        print(f"{i:3d} ok  {note}")
    _, sw = card.tx("80 14 04 00 03", "free space")
    print(f"done: {len(steps)} steps; free space now {int.from_bytes(_, 'big')} bytes")
    card.close()


if __name__ == "__main__":
    main()
