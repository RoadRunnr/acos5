"""ACOS5-EVO file layout for OpenSC, built step by step (no card access here).

Each step is (apdu_bytes, note). Steps are generated in pieces so they can be
reviewed separately.

Security Attribute Compact (tag 8C) for a DF:  8C 08 7F <7 SCBs>, SCB order
(access mode byte bits b7..b1):
    delete self, terminate, activate, deactivate, create DF, create EF, delete child
for an EF:
    delete self, terminate, activate, deactivate, write, update, read
SCB values: 00 = always, FF = never, 0n = SE record n must be satisfied,
4n = like 0n plus secure messaging.
"""
from evo_records import SecretNote, activate, at_pin, create_file, pin_record, se_record, select, update_record

LCSI_CREATION = bytes.fromhex("8A 01 01")


def fcp(fid: str, descriptor: str, sac: str, extra: str = "") -> bytes:
    """FCP body: file id (83), life cycle (8A), descriptor (82), extra TLVs, SAC (8C)."""
    return (bytes.fromhex("83 02") + bytes.fromhex(fid) + LCSI_CREATION
            + bytes.fromhex(descriptor) + bytes.fromhex(extra) + bytes.fromhex("8C 08 7F") + bytes.fromhex(sac))


def piece2_mf_and_global_files(so_pin: bytes, so_puk: bytes):
    steps = []

    # MF 3F00. Descriptor 82 02 3F 00 (DF), SE file of the MF = 0003 (8D 02 00 03).
    # SCBs: delete self 00 (always -> the card stays wipeable), terminate FF (never),
    #       activate / deactivate / create DF / create EF / delete child 01 (SO PIN, SE #1).
    steps.append((create_file(fcp("3F00", "82 02 3F 00", "00 FF 01 01 01 01 01", extra="8D 02 00 03")),
                  "create MF 3F00"))

    # Global PIN file 0001: internal linear fixed (FDB 0A), record length 0x15, 1 record.
    # SCBs: delete 01, terminate FF, activate 01, deactivate 01, write FF, update 01, read FF (never).
    steps.append((create_file(fcp("0001", "82 06 0A 00 00 15 00 01", "01 FF 01 01 FF 01 FF")),
                  "create global PIN file 0001"))
    steps.append((select("0001"), "select 0001"))
    steps.append((update_record(1, pin_record(so_pin, so_puk)), SecretNote("write SO PIN / SO PUK (global PIN 1)")))
    steps.append((activate("0001"), "activate 0001"))

    # Global SE file 0003: internal SE file (FDB 1C), record length 0x30, 1 record.
    # SCBs: delete 01, terminate FF, activate 01, deactivate 01, write 00, update 01, read 00 (always;
    # the driver needs to read SE files without a PIN).
    steps.append((create_file(fcp("0003", "82 06 1C 00 00 30 00 01", "01 FF 01 01 00 01 00")),
                  "create global SE file 0003"))
    steps.append((select("0003"), "select 0003"))
    steps.append((update_record(1, se_record(1, at_pin(0x01))), "SE #1: verify global PIN 1 (SO PIN)"))
    steps.append((activate("0003"), "activate 0003"))

    return steps


AID = b"ACOSPKCS-15v1.00"          # 41 43 4F 53 50 4B 43 53 2D 31 35 76 31 2E 30 30, as in carblue's script


def piece3_app_df(user_pin: bytes, user_puk: bytes, key1: bytes | None, key2: bytes | None, *,
                  sm: bool = False, bind: bool = False):
    """Application DF 4100 with PIN, key and SE files.

    sm:   write the SM keys 0x81/0x82 into 4102 and create the SM test files 4104/4105.
    bind: add security attributes expanded (AB) to DF 4100 that require SM MAC+enc (SE #6) for
          VERIFY, CHANGE REFERENCE DATA and RESET RETRY COUNTER. Needs sm.
    """
    if bind and not sm:
        raise ValueError("bind needs sm")
    if sm and (key1 is None or key2 is None):
        raise ValueError("sm needs both keys")
    from evo_records import ct_aes, cct_aes, sym_key_record, tlv, update_binary
    steps = []

    # EF.DIR 2F00 (transparent, 0x21 bytes): one application, AID, label "eCert", path 3F00 4100.
    # SCBs: delete 01, terminate FF, activate 01, deactivate 01, write FF, update 01, read 00.
    dir_rec = tlv(0x61, tlv(0x4F, AID) + tlv(0x50, b"eCert") + tlv(0x51, bytes.fromhex("3F00 4100")))
    steps.append((create_file(fcp("2F00", "82 02 01 00", "01 FF 01 01 FF 01 00",
                                  extra="80 02 00 %02X" % len(dir_rec))), "create EF.DIR 2F00"))
    steps.append((select("2F00"), "select 2F00"))
    steps.append((update_binary(dir_rec), "write EF.DIR"))
    steps.append((activate("2F00"), "activate 2F00"))

    # PKCS#15 application DF 4100, SE file 4103, DF name = AID.
    # SCBs: delete self 03 / activate 03 / deactivate 03 (SO PIN via local SE #3), terminate FF,
    #       create DF / create EF / delete child 01 (user PIN via local SE #1; key generation creates EFs).
    # With bind, the AB object holds one entry per command: 84 01 INS 9E 01 46 (INS 20 verify,
    # 24 change reference data, 2C reset retry counter; SCB 46 = SM MAC+enc with SE #6).
    sae = b"".join(bytes.fromhex(f"84 01 {ins:02X} 9E 01 46") for ins in (0x20, 0x24, 0x2C)) if bind else b""
    extra = "8D 02 41 03 " + tlv(0x84, AID).hex() + (tlv(0xAB, sae).hex() if sae else "")
    steps.append((create_file(fcp("4100", "82 02 38 00", "03 FF 03 03 01 01 01", extra=extra)), "create DF 4100"))
    steps.append((select("4100"), "select DF 4100"))

    # Local PIN file 4101: user PIN / user PUK (local PIN reference 0x81). Never readable.
    steps.append((create_file(fcp("4101", "82 06 0A 00 00 15 00 01", "03 FF 03 03 FF 01 FF")),
                  "create local PIN file 4101"))
    steps.append((select("4101"), "select 4101"))
    steps.append((update_record(1, pin_record(user_pin, user_puk)), SecretNote("write user PIN / user PUK (local PIN 1)")))
    steps.append((activate("4101"), "activate 4101"))

    # Local symmetric key file 4102: internal linear variable (FDB 0C), max record 0x26, 12 records.
    # Never readable; update needs the user PIN (SE #1), as in carblue. Write never: for a key file the card
    # checks the write SCB for PSO with a stored key (MSE CT + PSO ENCIPHER / DECIPHER). With the user PIN
    # there, the SM keys would encrypt and decrypt any data, so whoever can send commands after a login
    # could forge SM MACs and decrypt SM data. Secure messaging itself does not check this SCB.
    #   record 1 = key 0x81: AES-192 host authentication key (mutual authentication)
    #   record 2 = key 0x82: AES-192 secure messaging key
    steps.append((create_file(fcp("4102", "82 06 0C 00 00 26 00 0C", "03 FF 03 03 FF 01 FF")),
                  "create local key file 4102"))
    steps.append((select("4102"), "select 4102"))
    if sm:
        steps.append((update_record(1, sym_key_record(1, key1)), SecretNote("key 0x81 AES-192 (host auth)")))
        steps.append((update_record(2, sym_key_record(2, key2)), SecretNote("key 0x82 AES-192 (SM)")))
    steps.append((activate("4102"), "activate 4102"))

    # Local SE file 4103: record number == SE id, no holes.
    steps.append((create_file(fcp("4103", "82 06 1C 00 00 38 00 08", "03 FF 03 03 00 03 00")),
                  "create local SE file 4103"))
    steps.append((select("4103"), "select 4103"))
    se = [
        se_record(1, at_pin(0x81)),                                       # user PIN
        se_record(2, at_pin(0x81), cct_aes(0x82), ct_aes(0x82)),          # user PIN + SM (MAC + enc)
        se_record(3, at_pin(0x01)),                                       # SO PIN
        se_record(4, tlv(0xA4, tlv(0x83, b"\x81") + tlv(0x83, b"\x01") + tlv(0x95, b"\x08"))),  # user AND SO PIN
        se_record(5, cct_aes(0x82)),                                      # SM: MAC only
        se_record(6, cct_aes(0x82), ct_aes(0x82)),                        # SM: MAC + encryption
    ]
    for i, rec in enumerate(se, 1):
        steps.append((update_record(i, rec), f"local SE #{i}"))
    steps.append((activate("4103"), "activate 4103"))

    # SM test files (16 bytes each). SCB 4n = secure messaging with local SE #n.
    #   4104: read needs SM MAC+enc (SE #6), update needs SM MAC (SE #5)
    #   4105: read needs SM MAC (SE #5), update needs SM MAC (SE #5)
    sm_files = (("4104", "46", bytes(range(1, 17))), ("4105", "45", b"EVO SM MAC test.")) if sm else ()
    for fid, read_scb, content in sm_files:
        steps.append((create_file(fcp(fid, "82 02 01 00", f"00 FF 00 03 FF 45 {read_scb}", extra="80 02 00 10")),
                      f"create SM test file {fid}"))
        steps.append((select(fid), f"select {fid}"))
        steps.append((update_binary(content), f"write {fid} (plain, file still in creation state)"))
        steps.append((activate(fid), f"activate {fid}"))
    return steps


def piece4_pkcs15(serial: bytes, label: bytes = b"ACOS5-EVO", *, sm: bool = False, bind: bool = False):
    """PKCS#15 files. sm lists the SM keys in the SKDF; bind makes ODF, TokenInfo and the DFs
    readable only with SM MAC (read SCB 45)."""
    from evo_records import tlv, update_binary
    steps = []
    p = lambda fid: tlv(0x30, tlv(0x04, bytes.fromhex("3F00 4100") + bytes.fromhex(fid)))  # noqa: E731

    # PKCS#15 directory files, transparent. As in carblue: read and update always (OpenSC's
    # pkcs15-init updates them during key generation), deactivate needs the SO PIN (SE #3).
    # The driver stores certificates directly in the CDFs (not in separate files), hence the larger CDF sizes.
    dfs = [("4110", "03 00"), ("4111", "03 00"), ("4112", "01 00"), ("4113", "02 00"), ("4114", "18 00"),
           ("4115", "08 00"), ("4116", "08 00"), ("4117", "01 00"), ("4118", "01 00")]
    content = {} if not sm else {
        # EF.SKDF: the two AES-192 keys of 4102, listed so OpenSC/driver never overwrite those records.
        # genericSecretKey (PKCS#15 has no AES choice; OpenSC lists them as generic secret keys), 192 bit;
        # record length 0x1E = EVO record size
        "4113": b"".join(
            tlv(0x30, tlv(0x30, tlv(0x0C, name) + bytes.fromhex("03 02 06 C0 04 01 01"))
                + tlv(0x30, tlv(0x04, bytes([kid])) + bytes.fromhex("03 02 06 C0 03 02 04 B0 02 02 00")
                      + bytes([0x80 | kid]))
                + bytes.fromhex("A0 04 02 02 00 C0")
                + tlv(0xA1, tlv(0x30, tlv(0x30, tlv(0x04, bytes.fromhex("3F00 4100 4102"))
                                          + tlv(0x02, bytes([kid])) + tlv(0x80, b"\x1E")))))
            for kid, name in ((1, b"SM1"), (2, b"SM2"))),
    }
    # EF.AODF: user PIN (local 0x81) and SO PIN (global 0x01), as in carblue.
    content["4118"] = bytes.fromhex(
        "30 35 30 0A 0C 04 55 73 65 72 03 02 06 C0 30 03 04 01 01 A1 22 30 20 03 03 04 CC 00 0A 01 01"
        " 02 01 04 02 01 08 02 01 08 80 02 00 81 04 01 FF 30 06 04 04 3F 00 41 00"
        " 30 30 30 08 0C 02 53 4F 03 02 06 C0 30 03 04 01 02 A1 1F 30 1D 03 03 04 8F 00 0A 01 01"
        " 02 01 04 02 01 08 02 01 08 80 01 01 04 01 FF 30 04 04 02 3F 00")
    read_scb = "45" if bind else "00"
    for fid, size in dfs:
        steps.append((create_file(fcp(fid, "82 02 01 00", f"00 FF 00 03 FF 00 {read_scb}", extra="80 02 " + size)),
                      f"create PKCS#15 DF file {fid}"))
        steps.append((select(fid), f"select {fid}"))
        if fid in content:
            steps.append((update_binary(content[fid]), f"write {fid}"))
        steps.append((activate(fid), f"activate {fid}"))

    # EF.ODF 5031: pointers to PrKDF A0, PuKDF A1, SKDF A3, CDF A4, CDF_TRUSTED A5, CDF_USEFUL A6,
    # DODF A7, AODF A8 (PuKDF_TRUSTED 4112 left out: unsupported by OpenSC).
    odf = b"".join(tlv(tag, p(fid)) for tag, fid in (
        (0xA0, "4110"), (0xA1, "4111"), (0xA3, "4113"), (0xA4, "4114"),
        (0xA5, "4115"), (0xA6, "4116"), (0xA7, "4117"), (0xA8, "4118")))
    steps.append((create_file(fcp("5031", "82 02 01 00", f"03 FF 00 03 FF 00 {read_scb}",
                                  extra="80 02 00 %02X" % len(odf))), "create EF.ODF 5031"))
    steps.append((select("5031"), "select 5031"))
    steps.append((update_binary(odf), "write EF.ODF"))
    steps.append((activate("5031"), "activate 5031"))

    # EF.TokenInfo 5032: version 1, serial (card serial), manufacturer, label, tokenflags prnGeneration.
    # supportedAlgorithms omitted: the V2/V3 algorithm references in carblue's file are wrong for EVO.
    ti = tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, serial) + tlv(0x0C, b"Advanced Card Systems Ltd.")
             + tlv(0x80, label) + bytes.fromhex("03 02 04 20"))
    steps.append((create_file(fcp("5032", "82 02 01 00", f"00 FF 00 03 FF 00 {read_scb}", extra="80 02 00 C0")),
                  "create EF.TokenInfo 5032"))
    steps.append((select("5032"), "select 5032"))
    steps.append((update_binary(ti), "write EF.TokenInfo"))
    steps.append((activate("5032"), "activate 5032"))

    # Finally activate the application DF and the MF: from now on access conditions are enforced.
    steps.append((select("4100"), "select DF 4100"))
    steps.append((activate("4100"), "activate DF 4100"))
    steps.append((select("3F00"), "select MF"))
    steps.append((activate("3F00"), "activate MF"))
    return steps
