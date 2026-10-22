#!/usr/bin/env python3
"""Guarded APDU transport for the ACOS5-EVO.

Every APDU goes through SafeCard.tx(). It refuses commands that could lock the card
(life-cycle changes, card activation, writes to the card header block, SET BAUD RATE)
and logs every exchange to ~/.config/acos5evo/evo-apdu.log, PINs and keys redacted.
It also refuses UPDATE BINARY while the card may have no MF: on the older ACOS5,
UPDATE BINARY without an MF writes physical memory.
"""
import datetime
import os
import sys

from smartcard.scard import (SCARD_PCI_T0, SCARD_PCI_T1, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCARD_RESET_CARD,
                             SCARD_S_SUCCESS, SCARD_SCOPE_USER, SCARD_SHARE_EXCLUSIVE,
                             SCARD_UNPOWER_CARD, SCardConnect, SCardDisconnect,
                             SCardEstablishContext, SCardGetErrorMessage, SCardListReaders,
                             SCardReconnect, SCardReleaseContext, SCardStatus, SCardTransmit)

LOG = os.path.expanduser("~/.config/acos5evo/evo-apdu.log")


class Refused(Exception):
    pass


def check_safe(apdu: bytes) -> None:
    """Raise Refused for any APDU that could lock or irreversibly change the card."""
    if len(apdu) < 4:
        raise Refused("short APDU")
    cla, ins, p1, p2 = apdu[0], apdu[1], apdu[2], apdu[3]
    cla_plain = cla & 0xF3          # ignore SM bits (0x0C) in the class byte
    if ins == 0x12 and cla_plain == 0x80:
        raise Refused("Change Life Cycle (80 12) would leave the Manufacturer Stage")
    if ins == 0x32 and cla_plain == 0x80:
        raise Refused("SET BAUD RATE (80 32) rewrites the ATR")
    if ins == 0x10 and cla_plain == 0x80:
        raise Refused("Verify Transport Code (80 10) changes the life cycle stage")
    if ins == 0x44 and p1 == 0x01:
        raise Refused("Activate Card (00 44 01 ..) enters User Stage; zeroize no longer allowed")
    if ins == 0x04 and p1 == 0x01:
        raise Refused("Deactivate Card (00 04 01 ..) not needed")
    if ins in (0xD6, 0xD0, 0xDC, 0xE2) and p1 == 0xC1:
        raise Refused("write to card header block (offset C1xx: config / zeroize-disable bytes)")
    if ins == 0xD6 and (p1 & 0x80) and p1 != 0xC1:
        raise Refused("UPDATE BINARY with SFI/odd P1 - not used, refused to be safe")


def fcp_file_id(apdu: bytes):
    """The file id (tag 83) from the FCP of a plain CREATE FILE APDU, or None."""
    data = apdu[5:5 + apdu[4]] if len(apdu) > 5 else b""
    if len(data) < 2 or data[0] != 0x62:
        return None
    body, i = data[2:2 + data[1]], 0
    while i + 2 <= len(body):
        tag, ln = body[i], body[i + 1]
        if tag == 0x83 and ln == 2:
            return bytes(body[i + 2:i + 4])
        i += 2 + ln
    return None


def apdu_log_text(apdu: bytes, secret: bool = False) -> str:
    """Hex text for the log; a secret APDU is logged as its 5 byte header only."""
    if secret:
        return apdu[:5].hex(" ").upper() + " <data redacted>"
    return apdu.hex(" ").upper()


MF_UNKNOWN, MF_PRESENT, MF_ABSENT = "unknown", "present", "absent"


class SafeCard:
    # MF state for the UPDATE BINARY guard. Unknown at start: a successful SELECT shows the card is
    # initialized. A successful ZEROIZE removes the MF until a CREATE FILE of 3F00 succeeds.
    mf = MF_UNKNOWN

    def __init__(self, protocol=SCARD_PROTOCOL_T0, reader=None):
        # T=0 by default: under T=1 the EVO rejects case 4 APDUs carrying Le with 67 00
        rv, self.ctx = SCardEstablishContext(SCARD_SCOPE_USER)
        self._ok(rv, "context")
        rv, rdrs = SCardListReaders(self.ctx, [])
        self._ok(rv, "list readers")
        reader = reader if reader is not None else os.environ.get("EVO_READER")
        if reader is None:
            if len(rdrs) > 1:
                print(f"several readers, using {rdrs[0]!r}; set EVO_READER to choose", file=sys.stderr)
            self.reader = rdrs[0]
        else:
            matches = [r for r in rdrs if reader in r]
            if len(matches) != 1:
                raise RuntimeError(f"EVO_READER {reader!r} matches {len(matches)} of the readers {rdrs}")
            self.reader = matches[0]
        self.protocol = protocol
        rv, self.h, self.proto = SCardConnect(self.ctx, self.reader, SCARD_SHARE_EXCLUSIVE, protocol)
        if rv != SCARD_S_SUCCESS and protocol == SCARD_PROTOCOL_T0:
            # the contactless interface offers only T=1; fall back to it (evo_init.py sends no case 4 APDU)
            self.protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
            rv, self.h, self.proto = SCardConnect(self.ctx, self.reader, SCARD_SHARE_EXCLUSIVE, self.protocol)
        self._ok(rv, "connect")
        self.log(f"=== connect {self.reader} proto={self.proto}")

    @staticmethod
    def _ok(rv, what):
        if rv != SCARD_S_SUCCESS:
            raise RuntimeError(f"{what}: {SCardGetErrorMessage(rv)}")

    def log(self, line):
        os.makedirs(os.path.dirname(LOG), mode=0o700, exist_ok=True)
        with open(LOG, "a") as fh:
            fh.write(f"{datetime.datetime.now().isoformat(timespec='milliseconds')} {line}\n")

    def atr(self) -> bytes:
        rv, _, _, _, atr = SCardStatus(self.h)
        self._ok(rv, "status")
        return bytes(atr)

    def reset(self, cold=False):
        rv, self.proto = SCardReconnect(self.h, SCARD_SHARE_EXCLUSIVE, self.protocol,
                                        SCARD_UNPOWER_CARD if cold else SCARD_RESET_CARD)
        self._ok(rv, "reconnect")
        self.log("=== reset" + (" (cold)" if cold else ""))

    def tx(self, apdu, note="", secret=False):
        """Send one APDU (bytes or hex string). Returns (data, sw) with sw as int.

        secret: log the command without its data (key material). check_safe still sees the full APDU.
        """
        if isinstance(apdu, str):
            apdu = bytes.fromhex(apdu)
        check_safe(apdu)
        if apdu[1] == 0xD6 and self.mf != MF_PRESENT:
            raise Refused(f"UPDATE BINARY while the MF is {self.mf}: without an MF it may write physical memory")
        pci = SCARD_PCI_T0 if self.proto == SCARD_PROTOCOL_T0 else SCARD_PCI_T1
        rv, resp = SCardTransmit(self.h, pci, list(apdu))
        self._ok(rv, "transmit")
        data, sw = bytes(resp[:-2]), (resp[-2] << 8) | resp[-1]
        self.log(f">> {apdu_log_text(apdu, secret)}  {note}")
        self.log(f"<< {data.hex(' ').upper()} SW={sw:04X}")
        self._track_mf(apdu, sw)
        return data, sw

    def _track_mf(self, apdu, sw):
        ok = sw == 0x9000 or (sw >> 8) == 0x61
        cla, ins = apdu[0], apdu[1]
        if not ok:
            return
        if ins == 0x30 and cla & 0xF3 == 0x80 and sw == 0x9000:
            self.mf = MF_ABSENT
        elif ins == 0xE0 and cla == 0x00 and fcp_file_id(apdu) == b"\x3F\x00":
            self.mf = MF_PRESENT
        elif ins == 0xA4 and self.mf == MF_UNKNOWN:
            self.mf = MF_PRESENT

    def close(self):
        SCardDisconnect(self.h, SCARD_RESET_CARD)
        SCardReleaseContext(self.ctx)
