# ACOS5-EVO command reference

This page is for developers of the driver. It describes the commands of the ACOS5-EVO (contact interface, COS version `41 43 4F 53 05 04 32 C0`) as far as they are known.

> [!IMPORTANT]
> The commands on this page were **not** taken from the ACOS5-EVO reference manual. ACS gives that manual only on request, and it was not used for this page.

The page builds on the following public sources and prior work:

- The [ACOS5 page of the OpenSC wiki](https://github.com/OpenSC/OpenSC/wiki/ACOS5) and the [reference manual of the older ACOS5](https://raw.githubusercontent.com/wiki/OpenSC/OpenSC/attachments/wiki/ACOS5/ACOS5%2520Reference%2520Manual.pdf) (version 1.6) that the wiki provides. The ACOS5-EVO keeps most of these commands, but it uses other algorithm codes.
- The earlier ACOS5 driver work for OpenSC in the [`acos5` branch of pacew/OpenSC](https://github.com/pacew/OpenSC/tree/acos5), which the wiki page names
- This driver's support for the ACOS5-64 V2.00 and V3.00, from [carblue/acos5](https://github.com/carblue/acos5)
- The public functional specification of the ACOS5-EVO, which describes the card's features, life cycle, and file system, but no command layouts
- Tests with a real ACOS5-EVO card

Each command carries a mark that says how far its layout is confirmed:

| Mark | Meaning |
| --- | --- |
| V | Verified on a real ACOS5-EVO card |
| D | Used by the driver on the ACOS5-EVO and tested end to end through OpenSC |
| U | Present in the driver, not tested on the ACOS5-EVO |
| N | Documented layout, not verified on the ACOS5-EVO and not used by the driver |
| L | Lock or life cycle command. Listed for completeness. Never send it. |

Nothing reliable is known about these functions, so this page does not cover them: the key agreement (ECDH) command, CMAC as a standalone command, purse commands, and custom loadable commands. Do not guess their layouts on a card.

## Transport

The card has the following transport properties:

- Protocol: use T=0. The ATR offers T=0 and T=1, with T=1 as the default. Under T=1, the card rejects every case 4 command that carries Le with `67 00`. Under T=0, the card follows ISO/IEC 7816-3:2006, clause 12.2.5: Le is not sent, the card answers `61 XX`, and GET RESPONSE reads the data.
- Length: only short commands under T=0. Longer data uses command chaining (CLA bit `10`), for example RSA-4096 decipher with 512 bytes of input (D). Responses longer than 256 bytes come in several `61 XX` and GET RESPONSE rounds.
- CLA values: `00` ISO, `80` proprietary, `0C` ISO with secure messaging, `8C` proprietary with secure messaging (GET KEY, PUT KEY), `10` chaining. `1C`, chaining with secure messaging, works for PSO DECIPHER with one-byte data object lengths, with each block wrapped on its own and the MAC header over CLA `1C` (V, see [Secure messaging](#secure-messaging)). The card refuses BER-coded lengths (`81 xx`, `82 xx xx`) in these blocks.

## Status words

The following table lists the status words the card returns:

| SW | Meaning |
| --- | --- |
| `90 00` | Success |
| `61 XX` | XX response bytes available (T=0). Read them with GET RESPONSE. |
| `63 CX` | PIN verification failed, or retry counter query: X tries left |
| `67 00` | Wrong length. Also: a T=1 case 4 command with Le, GET KEY with extended Le, the ROM SHA-1 query. |
| `69 81` | Command incompatible with the file structure, for example READ BINARY of the card header on an initialized card |
| `69 82` | Security status not satisfied, for example READ BINARY on a key file |
| `69 83` | Authentication method blocked (PIN blocked) |
| `69 87` | Secure messaging sent although the access condition does not require it |
| `69 88` | Secure messaging data objects refused, for example a wrong MAC, BER-coded lengths in PSO DECIPHER, or GET KEY under SM with Le `FF` |
| `6A 82` | File not found |
| `6A 86` | Incorrect P1 or P2, for example file info index 0, or a PIN or key status query out of range |
| `6A 88` | Referenced data not found |
| `90 NN`, `95 NN` | Proprietary information, payload in SW2 (see [GET CARD INFO](#get-card-info-80-14-p1-p2-le-v)) |

On the older ACOS5 some codes meant other things (N):

- `69 88` was "verification failed" for PSO VERIFY CRYPTOGRAPHIC CHECKSUM and RECOVER SIGNED DATA.
- Secure messaging errors were `68 84`.
- `69 85` meant "no challenge" or "no MSE template".

## Command overview

The following table lists the known commands:

| CLA INS | Command | Mark |
| --- | --- | --- |
| `00 A4` | SELECT FILE | V |
| `00 C0` | GET RESPONSE | V |
| `00 B0` / `0C B0` | READ BINARY (plain / SM) | V |
| `00 D6` / `0C D6` | UPDATE BINARY (plain / SM) | V |
| `00 0E` | ERASE BINARY | U |
| `00 B2` | READ RECORD | V |
| `00 DC` | UPDATE RECORD | V |
| `00 E2` | APPEND RECORD | U |
| `00 E0` | CREATE FILE | V |
| `00 E4` | DELETE FILE | D |
| `00 44` (P1 `00`) | ACTIVATE FILE | V |
| `00 04` (P1 `00`) | DEACTIVATE FILE | N |
| `00 20` / `0C 20` | VERIFY (plain / SM) | V |
| `00 24` / `0C 24` | CHANGE REFERENCE DATA (plain / SM) | D / V |
| `00 2C` / `0C 2C` | RESET RETRY COUNTER (plain / SM) | V |
| `00 28` / `00 26` | ENABLE / DISABLE PIN VERIFICATION | N |
| `80 2E` | LOGOUT PIN | U |
| `80 8A` | DE-AUTHENTICATE KEY | U |
| `00 84` | GET CHALLENGE | V |
| `00 82` | EXTERNAL / MUTUAL AUTHENTICATE | V |
| `00 88` | INTERNAL AUTHENTICATE | V |
| `00 22` | MANAGE SECURITY ENVIRONMENT (SET) | D |
| `00 22 F2` / `F3` / `F4` | MANAGE SECURITY ENVIRONMENT STORE / RESTORE / ERASE | N |
| `00 46` | GENERATE KEY PAIR (RSA / EC) | D |
| `00 2A 9E 9A` | PSO COMPUTE DIGITAL SIGNATURE | D |
| `00 2A 80 84` | PSO DECIPHER (RSA private key) | D |
| `00 2A 80 84` (symmetric) | PSO DECIPHER with a symmetric key | U |
| `00 2A 84 80` | PSO ENCIPHER | U |
| `00 2A 00 A8` | PSO VERIFY DIGITAL SIGNATURE | N |
| `00 2A 90 80` | PSO HASH | N |
| `00 2A 8E 80` | PSO COMPUTE CRYPTOGRAPHIC CHECKSUM | V |
| `00 2A 00 A2` | PSO VERIFY CRYPTOGRAPHIC CHECKSUM | N |
| `00 2A 90 9E` | PSO RECOVER SIGNED DATA | N |
| `80 DA` | PUT KEY | V |
| `80 CA` | GET KEY | V |
| `80 14` | GET CARD INFO | V |
| `80 30` | ZEROIZE CARD USER DATA | V |
| `80 CA FF 00 00` | CLEAR CARD, older form (see [Card life cycle and wipe](#card-life-cycle-and-wipe)) | N |
| `00 D6 C1 91` / `00 D6 C1 92` | Write the operation mode byte / the zeroize disable byte | L |
| `80 12` | CHANGE LIFE CYCLE | L |
| `80 32` | SET BAUD RATE (rewrites the ATR) | L |
| `80 10` | VERIFY TRANSPORT CODE | L |
| `00 44` (P1 `01`) | ACTIVATE CARD | L |
| `00 04` (P1 `01`) | DEACTIVATE CARD | L |

## File system commands

These commands select, read, write, create, and delete files.

### SELECT FILE `00 A4` (V)

The following table lists the selection forms:

| P1 P2 | Data | Notes |
| --- | --- | --- |
| `00 00` | File ID (2 bytes) | Select by file ID. MF `3F 00`, current DF `3F FF`. |
| `04 00` | DF name (AID) | Used by the driver for the PKCS#15 application (U on the ACOS5-EVO) |

Under T=0 the answer is `61 XX`, and GET RESPONSE returns the FCI. The following example shows the FCI of the MF:

```text
6F 20  83 02 3F00          file ID
       88 01 00            SFI
       8A 01 05            life cycle status (05 = operational, activated)
       82 02 3F 00         file descriptor (DF)
       8D 02 00 03         SE file ID of this DF
       84 00               DF name (empty for the MF)
       8C 08 7F 00 FF 01 01 01 01 01   security attributes compact
       AB 00               security attributes expanded (empty)
```

Reserved file IDs: `3F00` MF, `2F01` ATR file under the MF, `3FFF` current DF, `FFFF` reserved for future use. `0000` is invalid.

### GET RESPONSE `00 C0 00 00 Le` (V)

Le is the XX from the preceding `61 XX`. Le `00` after a shorter `61 XX` fails at the reader with the PC/SC error "transaction failed". Always use the announced length.

### READ BINARY `00 B0 P1 P2 Le` (V)

P1 P2 is the offset (15 bits). Le is at most `FF` per command. Key files (FDB `09`, `19`) are never readable this way (`69 82`). Use GET KEY for them.

`00 B0 C1 xx 01` addresses the card header: the life cycle byte `C1 84`, the configuration mode byte `C1 91`, and the zeroize disable byte `C1 92`. On an initialized card these reads return `69 81`.

Not verified (N): P1 bit 7 set means SFI in the low 5 bits of P1 and P2 = offset. The SFI form is not allowed under secure messaging. Without an MF, READ BINARY reads physical memory.

### UPDATE BINARY `00 D6 P1 P2 Lc data` (V)

P1 P2 is the offset. Writes with P1 `C1` target the card header. `tools/safecard.py` refuses them: `C1 92` would permanently disable ZEROIZE.

Not verified (N): P1 bit 7 set is the SFI form, as for READ BINARY. Without an MF, UPDATE BINARY writes physical memory. On the ACOS5-EVO that window exists between ZEROIZE and CREATE FILE of the MF. `tools/safecard.py` therefore refuses UPDATE BINARY with any CLA after a successful ZEROIZE until CREATE FILE of `3F00` succeeds, and at start until a SELECT succeeds. It also refuses the SFI form.

### ERASE BINARY `00 0E P1 P2 [02 end]` (U)

P1 P2 is the start offset. The optional 2-byte data is the end offset (exclusive). Without data, the command erases to the end of the file.

### READ RECORD `00 B2 rec 04 Le` and UPDATE RECORD `00 DC rec 04 Lc data` (V)

P2 `04` means the record number is in P1. The internal PIN, key, and SE files are record files (see [Internal file record formats](#internal-file-record-formats-v)). APPEND RECORD `00 E2 00 00 Lc data` (U) adds a record to a linear variable or cyclic file.

Not verified (N): the low 3 bits of P2 select the record: `0` first, `1` last, `2` next, `3` previous, `4` record number in P1 (1-based). The high 5 bits of P2, if not zero, are an SFI. On a cyclic EF, P1 `00` with P2 `04` reads the current record. Only P2 `04` is verified.

### CREATE FILE `00 E0 00 00 Lc 62 L FCP` (V)

The new file is created in the current DF and becomes selected. The following table lists the FCP data objects:

| Tag | Length | Content |
| --- | --- | --- |
| `83` | 2 | File ID |
| `8A` | 1 | Life cycle status. Use `01` (creation), then ACTIVATE FILE. |
| `82` | 2 or 6 | File descriptor: `FDB 00`, followed by `00 MRL 00 NOR` for record files |
| `80` | 2 | File size (transparent EFs) |
| `88` | 1 | SFI (optional) |
| `8D` | 2 | SE file ID (DFs only) |
| `84` | var | DF name or AID (DFs only) |
| `8C` | var | Security attributes compact: `8C 08 7F <7 SCBs>` |
| `AB` | var | Security attributes expanded (SAE), optional |

The following table lists the file descriptor bytes (FDB):

| FDB | Type |
| --- | --- |
| `38` | DF (the MF uses the descriptor `3F 00`) |
| `01` | Transparent working EF |
| `02` / `04` / `06` | Linear fixed / linear variable / cyclic working EF (ISO values, not tested) |
| `09` | Internal RSA key EF (one key, private or public) |
| `19` | Internal ECC key EF (one key, private or public) |
| `0A` | Internal PIN EF (linear fixed) |
| `0C` | Internal symmetric key EF (linear variable) |
| `1C` | Internal security environment EF |

FDB bit `40` is the ISO/IEC 7816-4 shareable bit. `09` and `19` differ only in the category bits, so an RSA key EF and an EC key EF are the same kind of file with different key categories.

The FDB sets what a file does. The `8C` and `AB` attributes and the SE file that the DF's `8D` names set who may use it. Key EFs work at `5xxx` (V). Nothing on the card ties key EFs to an ID range. The IDs matter to the software that reads the layout: PKCS#15 (ISO/IEC 7816-15) expects EF.ODF at `5031` and EF.TokenInfo at `5032` in the application DF.

The security condition bytes (SCBs) in `8C 08 7F` follow the access mode byte, from bit 7 to bit 1:

- DF: delete self, terminate, activate, deactivate, create DF, create EF, delete child
- EF: delete self, terminate, activate, deactivate, write, update, read. Not verified (N): the fifth position is unused on a working EF.
- Key EF: delete self, terminate, activate, deactivate, MSE / PSO, put key, get key. The driver calls the fifth position CRYPTO. Verified (V): the fifth position governs PSO SIGN and PSO DECIPHER. Not verified (N): GENERATE KEY PAIR checks the put key condition of both key EFs.
- SE EF (N): delete self, terminate, activate, deactivate, MSE restore, MSE store / erase, read

The SCB values are the following:

- `00`: always
- `FF`: never
- `0n`: SE record n of the DF's SE file must be satisfied
- `4n`: like `0n`, plus secure messaging according to that SE record

Bit 7 of the SCB sets how the conditions of SE record n combine. This is verified (V) on the crypto position of a private RSA-2048 key EF with SE record 2 (user PIN, SM with MAC and encryption):

- Bit 7 clear (`0n`, `4n`): one condition of SE record n is enough. With SCB `42`, a verified user PIN alone allows plain PSO SIGN and PSO DECIPHER, and SM alone allows PSO SIGN without a verified PIN.
- Bit 7 set (`8n`, `Cn`): every condition of SE record n must be met. With SCB `C2`, plain PSO SIGN and PSO DECIPHER return `69 82` after a verified PIN, and PSO SIGN under SM returns `69 82` without a verified PIN.

The following table shows the verified results for four crypto SCBs on a private RSA-2048 key EF. MSE SET in plain was accepted in every case, so the card checks the crypto SCB at the PSO command and not at MSE SET:

| Crypto SCB | Plain, PIN verified | SM, PIN verified | SM sign, no PIN verified |
| --- | --- | --- | --- |
| `42` (SE #2, one condition) | Sign and decipher accepted | Sign and decipher work | Works |
| `C2` (SE #2, all conditions) | Sign and decipher `69 82` | Sign and decipher work | `69 82` |
| `45` (SE #5, SM MAC) | Sign and decipher `69 82` | Sign works (response in `81`), encrypted decipher `69 87` | Works |
| `46` (SE #6, SM MAC and encryption) | Sign and decipher `69 82` | Sign and decipher work | Works |

Plain sign without a verified PIN returns `69 82` for all four SCBs. Only `C2` requires both the user PIN and SM. The profile option `+bound` uses `C2`.

The rule is verified on the crypto position only. The other key EF positions probably follow it (N). Take a private key EF with get key SCB `4n`, where SE record n holds a CCT or CT and a PIN. GET KEY under SM alone, without the PIN, would then read it. Whoever holds the SM key of that SE record could read the private key. Put key `4n` would likewise accept SM alone or the PIN alone.

SE record 4 of the layout of `tools/evo_init.py` (`A4 09 83 01 81 83 01 01 95 01 08`) holds two PINs. An SCB `04` accepts either PIN. Both PINs would need `84`, which is not tested. No file in the layout uses SE record 4.

#### Security attributes expanded

The SAE (tag `AB`) applies only to the MF and DFs and governs the commands in that DF (N). Verified (V): an SAE on an EC key EF is accepted by CREATE FILE but not enforced. An SAE on a DF binds every INS it names. With `AB 06 84 01 2A 9E 01 45` on a DF, the card refuses a plain PSO (INS `2A`) in that DF with `69 82` and accepts it under SM with a MAC. This also holds for ECDSA signing, which the key EF SCBs cannot bind. `tools/evo_init.py --bind-sign` uses it for PSO and GENERATE KEY PAIR in DF 4100. The SAE holds at most 32 bytes: pairs of an access mode data object (AMDO) and security condition data objects (SCDO), repeated. The following table lists the data objects:

| Item | Meaning |
| --- | --- |
| AMDO tag `8x` | The low nibble selects the command bytes that follow: bit 3 CLA, bit 2 INS, bit 1 P1, bit 0 P2 (V: `84 01 <INS>`) |
| SCDO `90 00` | Always |
| SCDO `97 00` | Never |
| SCDO `9E 01 <SCB>` | SCB as in the compact form (V: `9E 01 46`) |
| SCDO `A4 L <AT>` | Allowed if the authentication template is satisfied |
| SCDO `A0 L <SCDOs>` | At least one of the SCDOs |
| SCDO `AF L <SCDOs>` | All of the SCDOs |

Not verified (N): the first AMDO that matches the command decides, and later AMDOs are not checked. For example, `86 02 22 F2 97 00` means MSE STORE never.

### DELETE FILE `00 E4 00 00 02 FID` (D)

Deletes the file in the current DF. The DF's "delete child" SCB and the file's "delete self" SCB apply.

### ACTIVATE FILE `00 44 00 00 [02 FID]` (V)

Moves the selected or given file from creation (`01`) to operational activated (`05`). From then on the card enforces the SCBs. Do not confuse it with `00 44 01 ..`, ACTIVATE CARD.

### DEACTIVATE FILE `00 04 00 00 [02 FID]` (N)

Deactivates the selected or given file. Afterwards the card refuses every command on the file except ACTIVATE FILE. Under SM, Lc must be `00` (the selected file). Do not confuse it with `00 04 01 ..`, DEACTIVATE CARD.

## Security and authentication

These commands verify PINs, authenticate keys, and set the security environment.

### VERIFY `00 20 00 ref [Lc PIN]` (V)

ref is a global PIN `01` to `1F` or a local PIN `81` to `9F` (bit 7 = DF-local). Without data, the command returns `63 CX` (tries left), or `90 00` if the PIN is already verified. A wrong PIN gives `63 CX`, and a blocked PIN gives `69 83`. The retry counters persist across reset and power cycle, and the card enforces them in the manufacturer stage.

SM form (V): `0C 20 00 ref` with the PIN in an encrypted `87` object. On a DF whose SAE requires SM for INS `20` (`tools/evo_init.py --sm --bind`), the SM form works: `90 00`, or for a wrong PIN an inner `63 CX` in the `99` object. The card refuses the plain form there with `69 82`. Where SM is not required, the card refuses the SM form with `69 87`.

### CHANGE REFERENCE DATA `00 24 00 ref Lc oldPIN || newPIN` (D)

SM form (V): `0C 24`, with the old and the new PIN in an encrypted `87` object. Works where the DF requires SM for INS `24`. Refused with `69 87` where it does not.

Not verified (N): P1 `01` means the data holds only the new PIN, and the current PIN must be verified first.

### RESET RETRY COUNTER `00 2C 00 ref Lc PUK || newPIN` (V)

Unblocks the PIN with its resetting code (PUK) and sets the new PIN.

SM form (V): `0C 2C`, with the PUK and the new PIN in an encrypted `87` object. Works where the DF requires SM for INS `2C`. Refused with `69 87` where it does not.

Tested with a PUK that differs from its PIN, for the user PIN under SM and for the SO PIN in plain (V). The card checks the PUK, not the PIN. The PIN given as the PUK is refused, and only the PUK's retry counter drops by one. A PIN blocked by eight wrong VERIFY commands is unblocked with the right PUK.

### ENABLE and DISABLE PIN VERIFICATION `00 28 P1 ref` / `00 26 P1 ref` (N)

P1 `00`: the data is the current PIN. P1 `01`: no data, and the PIN must be verified first. A disabled PIN need not be presented for the access rights tied to it, and VERIFY on it answers `69 84`.

### LOGOUT PIN `80 2E 00 ref` and DE-AUTHENTICATE KEY `80 8A 00 ref` (U)

Clear the verified state of a PIN or a key.

### GET CHALLENGE `00 84 00 00 Le` (V)

Le is `08` or `10`. The 3DES authentication uses `08`. Le `10` also starts each AES secure messaging command (see [Secure messaging](#secure-messaging)).

### MUTUAL AUTHENTICATE `00 82 00 ref 20 RNDh || E(RNDc)` (V)

After GET CHALLENGE with 16 bytes RNDc, the data is a 16-byte host random RNDh followed by the AES encryption of RNDc with the symmetric key `ref`. The card answers `61 10`, and GET RESPONSE returns E(RNDh). The driver's secure messaging uses static keys and does not use this command.

Details that are not verified (N):

- Lc is twice the challenge length. The cipher is AES-ECB, one block each, with the algorithm of the key record (AES-192 for algorithm `24`). The card authenticates the host from the second half. The host authenticates the card by comparing the GET RESPONSE data with its own E(RNDh).
- `69 83` means the key is blocked (error counter used up). `63 CX` means a wrong cryptogram with X tries left.
- One command does both directions. No separate INTERNAL AUTHENTICATE step exists on this path.
- An SE record can make the authenticated key an access condition: `A4 06 83 01 <key ID> 95 01 80` (usage `80` = key authenticated, `08` = PIN verified, `88` = both). The key ID is written without the local bit (key `81` as `01`). An SCB that points at such a record then requires a mutual authentication with that key.

The functional specification (sections 5.5 and 5.6) says that mutual authentication uses two keys of the same algorithm and length, a card key KC and a terminal key KT. It also says the card generates a session key KS automatically after the procedure, for AES or 3DES. The card keeps KS internal, so the host must derive the same KS to use it.

An SE record refers to the session key with `84 00` in its CCT or CT, without `83`. A CCT with both `83` and `84` gets `69 87` for an SM read, before and after a mutual authentication. Verified (V) for a CCT with `84 00` and no `83`:

- Before any mutual authentication in the card session, an SM read gets `69 87` (no session key).
- After a mutual authentication, a wrong MAC gets `69 88`. The session key stays for later commands without a new authentication.
- With 3DES keys, the session key is known and works. See [3DES session key](#3des-session-key-v).
- With AES keys, the card accepts both authentication forms and forms a session key, but its derivation is not known. The 3DES derivation with 8-byte halves of the 16-byte challenges does not match.

The functional specification (section 6.2) says SM for authenticity is not replayable. That holds for the session key path and for 3DES, but not for the static AES key, because the static AES MAC does not include the challenge (see [Secure messaging](#secure-messaging)).

The older ACOS5 derived its DES and 3DES session keys as follows (N). Let RE = E(RNDc) under KT and RI = E(RNDt) under KC. The 3DES session key is `KsL || KsR`:

```text
KsL = KC(left)  * RE  * KT(left)  * RI
KsR = KC(right) * ~RE * KT(right) * ~RI
```

For single DES, `KS = KC * RE * KT * RI`. The operator `*` is not defined. With XOR as the operator, this formula does not match on the ACOS5-EVO (V: `69 88`).

#### 3DES session key (V)

The 3DES session key works on the ACOS5-EVO with the derivation of the driver's ACOS5-EVO branch (`sm_cwa_initialize`). It was tested with two 2-key 3DES keys in the key file of a DF: key `81` = KT and key `82` = KC, record algorithm `14`. The test file's read SCB points at an SE record with CCT `B4 08 84 00 95 01 30 80 01 13`.

1. GET CHALLENGE `00 84 00 00 08` gives RNDc.
2. EXTERNAL AUTHENTICATE `00 82 00 81 08 3DES(KT, RNDc)` gives `90 00`.
3. INTERNAL AUTHENTICATE `00 88 00 82 08 RNDt` gives `61 08`. GET RESPONSE returns 3DES(KC, RNDt).
4. Compute `D = RNDc[4:8] RNDt[0:4] || RNDc[0:4] RNDt[4:8] || RNDc[0:4] RNDt[4:8]`. The session MAC key is `3DES-ECB(KT, D)` and the session encryption key `3DES-ECB(KC, D)`, each 24 bytes with odd parity.
5. Send each SM command in the static 3DES format (see [Secure messaging with a static 3DES key](#secure-messaging-with-a-static-3des-key-v)) with the session keys: GET CHALLENGE 8 = SSC, command MAC with IV = SSC+1, response MAC with IV = SSC+2.

With a CT `B8 08 84 00 95 01 30 80 01 13` next to the CCT, encrypted READ BINARY and UPDATE BINARY work as with a static key. The single combined command `00 82 00 81 10 RNDt || E(RNDc)` with one key also works: the same derivation then uses KT = KC = that key.

Observed details:

- The second and third 8-byte blocks of D are equal, so both keys have the form K1 || K2 || K2. 3DES-EDE with K3 = K2 is single DES under K1, so each session key is a 56-bit DES key in effect.
- The MAC key depends only on KT, the encryption key only on KC.
- The card needs a GET CHALLENGE before each SM command. The driver's framing for the older ACOS5 (SSC = RNDc, no new GET CHALLENGE) gets `69 85`.
- An initial value `87 08` in the CCT does not change the MAC IV. The card still uses SSC+1.
- The driver's branch for the older ACOS5 (D ends with `RNDt[0:4] RNDc[4:8]`) gets `69 88`.
- A command sent again unchanged gets `69 88`, right after the original command and after a new GET CHALLENGE.

The driver's ACOS5-EVO secure messaging uses the static AES keys and does not use session keys.

#### The driver's 3DES path

The driver has a 3DES authentication path for the older ACOS5 (`acos5/src/no_cdecl.rs`, `acos5/src/sm.rs`). The ACOS5-EVO secure messaging path does not use it. External and internal authentication work on the ACOS5-EVO (V). The session start is U:

- External authentication: GET CHALLENGE with 8 bytes RC, then `00 82 00 <ref> 08 3DES-ECB(Kh, RC)` (case 3). Success is SW2 `00`. The key has 24 bytes, and ref is not zero with `ref & 7F <= 1F`.
- Internal authentication: `00 88 00 <ref> 08 RH 08` (case 4) with a random 8-byte RH. The response must equal `3DES-ECB(Kc, RH)`.
- Session start (`sm_cwa_initialize`): external authentication with ref `81` and the host key Kh, SSC = RC, then internal authentication with ref `82` and the card key Kc. The derivation input is `RC[4..8] RH[0..4] RC[0..4] RH[4..8]`, followed by `RC[0..4] RH[4..8]` (ACOS5-EVO branch) or `RH[0..4] RC[4..8]`. KSenc = 3DES-ECB(Kc, input) and KSmac = 3DES-ECB(Kh, input), each with odd parity. The SSC (last 2 bytes, big-endian) is incremented before the command MAC and again before the response MAC. The MAC is 3DES-CBC with pad `80` and IV = SSC. The driver code marks the ACOS5-EVO case as unfinished.
- In the driver, ERASE BINARY and DELETE FILE on a file with SCB `4n` still go through this 3DES path on the ACOS5-EVO (`acos5/src/lib.rs`, erase_binary and delete_file). VERIFY, READ, and UPDATE take the ACOS5-EVO AES path.

### EXTERNAL AUTHENTICATE with 3DES `00 82 00 ref 08 E(RNDc)` (V)

The 3DES authentication of the older ACOS5 works on the ACOS5-EVO without changes. It was tested with two 3DES-168 keys in the key file of a DF: the terminal key KT (key `81`) and the card key KC (key `82`). Both records had key type `03`, error counter `88`, and algorithm `14`.

The following table lists the commands and the card's answers:

| Step | Command | Answer |
| --- | --- | --- |
| GET CHALLENGE | `00 84 00 00 08` | `90 00`, 8 bytes RNDc |
| EXTERNAL AUTHENTICATE with KT | `00 82 00 81 08 3DES-ECB(KT, RNDc)` | `90 00` |
| INTERNAL AUTHENTICATE with KC | `00 88 00 82 08 RNDt` | `61 08` |
| GET RESPONSE | `00 C0 00 00 08` | 3DES-ECB(KC, RNDt), `90 00` |
| EXTERNAL AUTHENTICATE, wrong cryptogram | `00 82 00 81 08 <wrong>` | `63 C7` (seven tries left) |
| EXTERNAL AUTHENTICATE without GET CHALLENGE | `00 82 00 81 08 <any>` | `69 85` |

RNDt is an 8-byte host random. A correct cryptogram after a wrong one gives `90 00` again. The key references are local (bit 7 set) and refer to the key file of the current DF.

The combined form of the older card works too: after GET CHALLENGE 8, `00 82 00 81 10 RNDt || 3DES(K, RNDc)` gives `61 08`, and GET RESPONSE returns 3DES(K, RNDt). After either form, the 3DES session key works (see [3DES session key](#3des-session-key-v)).

### INTERNAL AUTHENTICATE `00 88 00 ref 08 RNDt` (V)

The card encrypts the 8-byte host challenge RNDt with the 3DES key `ref` and answers `61 08`. GET RESPONSE returns 3DES-ECB(K, RNDt). Under T=0 the host sends the command without Le. With an AES key (V), `00 88 00 82 10 RNDh` gives `61 10`, and GET RESPONSE returns AES-ECB(K, RNDh). EXTERNAL AUTHENTICATE with AES is `00 82 00 81 10 AES(KT, RNDc)` after GET CHALLENGE 16 and gives `90 00` (V).

### MANAGE SECURITY ENVIRONMENT `00 22 01 tag Lc CRT` (D)

P1 `01` is SET for computation. P2 is the tag of the control reference template (CRT): `B6` DST, `B8` CT, `B4` CCT, `AA` HT, `A4` AT. The template holds the following data objects:

```text
80 01 <algo>     algorithm reference
81 02 <FID>      key file ID (asymmetric)
83 01 <keyref>   key reference (symmetric)
87 L  <IV>       initial value (symmetric CBC)
95 01 <usage>    40 = private key / compute, 80 = public key / verify-encipher
```

The bit meanings follow ISO/IEC 7816-4:2005. The following table lists the usage qualifier bits (tag `95`, table 35):

| Bit | Meaning |
| --- | --- |
| `80` | Verification (DST, CCT), encipherment (CT), external authentication (AT), key agreement (KAT) |
| `40` | Computation (DST, CCT), decipherment (CT), internal authentication (AT), key agreement (KAT) |
| `20` | SM in the response data field (CCT, CT, DST) |
| `10` | SM in the command data field (CCT, CT, DST) |
| `08` | User authentication, password based (AT) |
| `04` | User authentication, biometry based (AT) |

So `C0` combines compute and verify, `95 01 30` in the SM records of the SE file means SM in command and response, and `95 01 08` in an AT means PIN authentication. Not verified (N): in a CCT or CT of an SE record, bits `10` and `20` make the template usable for SM, and bit `40` for PSO.

The following table lists the MSE P1 bits (ISO/IEC 7816-4:2005, table 78):

| P1 bits | Meaning |
| --- | --- |
| `10` | SM in the command data field |
| `20` | SM in the response data field |
| `40` | Computation, decipherment, internal authentication, key agreement |
| `80` | Verification, encipherment, external authentication, key agreement |
| Low nibble `1` | SET |
| `F2` / `F3` / `F4` | STORE / RESTORE / ERASE (P2 = SE identifier) |

ISO cards usually take `41`, `81`, or `C1` for SET. The ACOS5-EVO uses `01`, SET without usage bits (D).

Not verified (N): STORE `00 22 F2 <id> 00` writes the accumulated CRTs as a new record `<id>` of the current SE file and fails if the ID exists. RESTORE `00 22 F3 <id> 00` loads record `<id>` as if set by MSE SET (`6A 83` if not found). ERASE `00 22 F4 <id> 00` erases it. They check the SE file's MSE store and restore SCBs. CRTs set by MSE SET accumulate in RAM, and SELECT FILE clears them. `83`, `84`, and `81` must not appear together in one CRT.

The CRTs come in tag pairs (ISO/IEC 7816-4:2005, table 32): AT `A4`/`A5`, KAT `A6`/`A7`, HT `AA`/`AB`, CCT `B4`/`B5`, DST `B6`/`B7`, CT `B8`/`B9`. MSE P2 names only the even tags, and the ACOS5-EVO uses only those.

The following table lists the control reference data objects (table 33) and their use on the ACOS5-EVO:

| Tag | Meaning | ACOS5-EVO |
| --- | --- | --- |
| `80` | Cryptographic mechanism reference | Used |
| `81` | File reference | Used (key EF) |
| `82` | DF name | Not used |
| `83` | Secret key reference, public key reference, or reference data qualifier | Used (symmetric key, PIN in AT) |
| `84` | Private key reference, or reference for computing a session key | `84 00` in a CCT or CT selects the session key (V, see [3DES session key](#3des-session-key-v)). Not together with `83`: the card then answers `69 87`. |
| `85` to `87` | Initial check block (`87` with L = k: initial value) | `87` used (IV) |
| `88` to `93` | Auxiliary data (challenge, counters, time stamp) | Not used |
| `94` | Challenge or data element for deriving a key | Not used |
| `95` | Usage qualifier | Used |
| `8E` | Cryptogram content reference (CT) | Not used |

The following table lists the algorithm references:

| CRT | Algorithm | Use | Mark |
| --- | --- | --- | --- |
| DST `B6` | `20` | RSA sign | D |
| DST `B6` | `22` | RSA key pair generation | D |
| DST `B6` | `40` | ECDSA sign | D |
| DST `B6` | `42` | EC key pair generation | D |
| DST `B6` | `21` | RSA verify (PSO VERIFY DIGITAL SIGNATURE) | N |
| DST `B6` | `41` | ECDSA verify (PSO VERIFY DIGITAL SIGNATURE) | N |
| CT `B8` | `24` | RSA decipher / encipher | D |
| CT `B8` | `10` / `11` | DES ECB / CBC | U |
| CT `B8` | `12` / `13` | 3DES ECB / CBC (`13` verified in an SM CT with a static 3DES key and with the session key) | U / V |
| CT `B8` | `14` / `15` | AES ECB / CBC (`15` verified in an SM CT) | U / V |
| CCT `B4` | `1D` | AES CMAC (verified in an SM CCT) | V |
| CCT `B4` | `13` | 3DES MAC (verified in an SM CCT with a static 3DES key) | V |
| CCT `B4` | `11` | DES MAC (refused with `69 88` for a 3DES key) | U |
| HT `AA` | `80` `81` `82` `84` `88` | SHA-1 / -224 / -256 / -384 / -512 | U |

Key generation sends two MSEs: a DST with `95 01 40` and the private key file ID, then a DST with `95 01 80` and the public key file ID. Signing uses a DST with algorithm `20` or `40` and `95 01 40`. RSA signing also sets a CT (algorithm `24`), so that DigestInfos other than SHA-1 and SHA-256 can go through decipher. ECDSA takes no CT: the card rejects it.

The following details are not verified (N):

- MSE uses only P1 `01` with the tags `B6` (DST), `B8` (CT), and `AA` (HT). AT `A4` and CCT `B4` appear only in SE records. No MSE with a KAT `A6` is known.
- The data objects in an MSE are only `80`, `81`, `83`, `87`, and `95`.
- The usage byte for sign, verify, and decipher can be `95 01 C0` instead of `40`. Verified (V) for EC signing: a DST with `95 01 C0` gives the same valid signature as with `40`.
- A symmetric CT has the form `B8 L 80 01 <algo> 87 L <IV> 83 01 <keyref> 95 01 <usage>`, where `<keyref>` is the key reference without the local bit `80` (key `81` is written as `01`).
- No CT is known for EC keys.

## Internal file record formats (V)

The card's internal files hold records in the following formats.

PIN EF (FDB `0A`), one record per PIN, record number = PIN ID:

```text
C1 <tries> <len> PIN... <tries> <len> PUK...
   C1     = valid | resetting code present | PIN ID 1
   tries  = high nibble maximum retries, low nibble retries left (for example 88)
```

The PIN and the PUK each have their own retry counter (V).

Symmetric key EF (FDB `0C`), one record per key:

```text
<80|id> 03 FF FF <error counter> <algo> <key bytes>
   algo 22 / 24 / 28 = AES-128 / -192 / -256, 14 = 3DES-168
```

The first byte has bit 7 set (valid) and the key ID in the low 5 bits. A 3DES-168 record `<80|id> 03 FF FF 88 14 <24-byte key>` works for external and internal authentication (V).

Not verified (N): `03` is the key type. Bit 0 means external authentication capable, and an error counter follows. Bit 1 means internal authentication capable, and a 2-byte usage counter follows (`FF FF` = unlimited). The usage counter comes before the error counter. The error counter has the form `<max | left << 4>`, for example `88`.

An activated key file refuses UPDATE RECORD on its free records with `69 82`, even with the update condition met (V). `tools/evo_init.py` therefore writes the key records while the key file is still in the creation state. Not tested: APPEND RECORD, and UPDATE RECORD of an existing record.

Security environment EF (FDB `1C`), one record per SE:

```text
80 01 <SE ID>  followed by CRTs, for example:
A4 06 83 01 <PIN ref> 95 01 08                       user verification (AT)
A4 09 83 01 81 83 01 01 95 01 08                     two PINs (both only with SCB 8n, not tested)
B4 09 83 01 <key> 95 01 30 80 01 1D                  SM MAC, AES-CMAC (CCT)
B8 09 83 01 <key> 95 01 30 80 01 15                  SM encryption, AES-CBC (CT)
A4 06 83 01 <key> 95 01 80                           key authenticated by MUTUAL AUTHENTICATE (N)
```

RSA and EC key EFs are written by GENERATE KEY PAIR or PUT KEY. Their content is readable only with GET KEY.

## Asymmetric cryptography

These commands generate, import, read, and use RSA and EC keys.

### GENERATE KEY PAIR `00 46 00 00` (D)

The two MSEs from [MANAGE SECURITY ENVIRONMENT](#manage-security-environment-00-22-01-tag-lc-crt-d) come first.

RSA: `00 46 00 00 02 <len code> <type>`, or with an explicit exponent `00 46 00 00 12 <len code> <type> <16-byte public exponent>`:

- The len code is the modulus length in bits divided by 128 (`10` = 2048, `20` = 4096). Both sizes are verified.
- The type is `01` sign, `02` decipher, or `03` both. Add 3 for the CRT form (`04` to `06`).
- Not verified (N): len code `00` is a second form, `00 46 00 00 12 00 06 <16-byte public exponent>`, CRT for sign and decipher. The modulus length then probably comes from the size of the key EF.

EC: `00 46 00 00 01 <curve>`, with curve `01` P-224, `02` P-256, `03` P-384, `04` P-521. All four are verified.

RSA-4096 generation took more than ten minutes on an ACOS5-EVO.

SM form: `0C 46` with the data in a plain `81` object (MAC only), after plain MSEs. It works (V) for RSA-2048 on key EFs whose SCBs require SM. The card refuses it with `69 87` on key EFs without SM in their SCBs, and for EC keys in every case tested, also under a DF SAE that requires SM for INS `46`. Under such an SAE the card refuses the plain form too (`69 82`), so EC keys cannot be generated in that DF. Import them instead.

### GET KEY `80 CA P1 P2 Le` (V)

Reads the key EF that is selected or referenced. P1 P2 is the offset. Le is at most `FF`, and extended Le gives `67 00`. Read the file in chunks.

The key EF's read SCB controls GET KEY. The driver creates public key EFs with read always, so GET KEY works on them. It creates private key EFs with read never, so GET KEY on them returns `69 82`, even after a verified user PIN. The private key is therefore not readable in the driver's layout.

SM form (V): `8C CA P1 P2` with `97 01 Le`. `0C CA` gives `6D 00`. On an RSA-2048 public key EF with read SCB `45` (SM MAC), the card answers with the data in a plain `81` object. Le `E0` works: the 277-byte public key record comes in two chunks, at offsets `0000` and `00E0`. Le `F0` returns 240 bytes, the limit. Le `FF` is refused with `69 88`. On a public key EF with read always, the card refuses the SM form with `69 87`.

EC public key EF content:

```text
00 <curve 01..04> <partner private key FID> 0A <format 02/03/04> <X [Y]>
```

P-224 is stored uncompressed (`04`), P-256 to P-521 compressed (`02` or `03`).

Not verified (N):

- A private key EF holds a 5-byte header followed by the key. An EC private key EF has n + 5 bytes for an n-byte scalar, which starts at offset 5. File sizes for CREATE FILE: EC private n + 5, RSA private CRT (n/2) * 5 + 5, RSA public n + `15`, with n the field or modulus length in bytes.
- When the SE record behind the get key SCB has a CT, the card answers `87 L 01 E(data) 99 02 SW 8E 04 MAC`, after `61 XX` and GET RESPONSE under T=0. E is AES-CBC with IV(response) = SSC+2. With padding indicator `01`, the host drops `16 - Le mod 16` bytes. The chunks have at most `E8` bytes, starting at the requested offset.

### PUT KEY `80 DA P1 P2 Lc data` (V)

Imports key material into a key EF (FDB `09` RSA, `19` EC) that already exists and is selected. P1 P2 is the 16-bit big-endian offset into the key EF. Data longer than `FF` bytes is split into chunks of `FF` bytes, with the offset advanced for each chunk. Not verified (N): CLA `90` (chaining bit) marks a continued block.

No MSE is needed, unlike for GENERATE KEY PAIR. The key EF's own update condition applies, so verify the needed PIN first (the user PIN in the driver's layout). After writing, activate the key EF with ACTIVATE FILE (`00 44 00 00`) before use.

SM form (V): `8C DA` with the record in an encrypted `87` object. It works on key EFs whose update SCB requires SM: the public record returns `63 01`, then the private record `90 00`. On a key EF without SM in its update SCB, the card refuses it with `69 87`. With CLA `0C DA` the card answers `6D 00`.

Not verified (N): the symmetric form, also for GET KEY, has P1 `01` and P2 = record number in the symmetric key EF.

`90 00` means success. `63 01` also counts as success, but it means the card could not confirm its pairwise consistency test: the matching counterpart key is missing or does not match. When the public and the private EF of a pair are both written and agree, the second write returns `90 00`. Write the public EF first, so that the private record's pairwise test passes.

Each record starts with a 5-byte header:

```text
<type> <len/curve> <partner FID hi> <partner FID lo> <marker>
```

The header fields are the following:

- type: RSA `00` public, `03` private non-CRT, `06` private CRT. EC `00` public, `01` / `02` / `03` private (1 sign, 2 decipher, 3 both), the same key type code that GENERATE KEY PAIR uses.
- len/curve: RSA modulus bits divided by 128 (`10` = 2048, `20` = 4096). EC curve code `01` to `04` (P-224 to P-521).
- partner FID: the file ID of the matching public or private counterpart, used for the pairwise test.
- marker: RSA `03`, EC `0A`. Generated keys, RSA and EC, show `0A` (V). Not verified (N): the byte holds flags, with bit 0 key complete and bit 1 validated (pairwise test passed). The meaning of bit 3 is not known.

EC keys (V): write the complete record, header and body, in a single PUT KEY at offset 0 (`80 DA 00 00 Lc <record>`). Writing at offset 5 is rejected with `6A 86`. The following table lists the body:

| Key | Body after the 5-byte header |
| --- | --- |
| EC public | The public point as the card stores it: P-224 uncompressed (`04` X Y), P-256 to P-521 compressed (`02` or `03` X) |
| EC private | The raw private scalar, field length bytes |

A P-256 key imported this way produces ECDSA signatures that verify against the known public key.

RSA keys (V): write the body in components at their offsets, and the header last. The following table lists the body:

| Key | Body |
| --- | --- |
| RSA public | Public exponent `e` (16 bytes, left-padded) at offset 5, modulus `N` at offset `15` (21) |
| RSA private CRT | `P \|\| Q \|\| DMP1 \|\| DMQ1 \|\| IQMP` at offset 5, each component half the modulus length (128 bytes for 2048) |
| RSA private non-CRT | Private exponent `D` (modulus length bytes) at offset 5 |

`IQMP` is `q^-1 mod p`, the usual CRT coefficient. A non-CRT private key EF stores only `D` and takes `N` from the paired public EF that the header's partner FID names, so import the public EF with it. RSA-2048 keys imported in both forms produce PKCS#1 v1.5 signatures that verify against the known public key. To sign, set MSE DST algorithm `20` and CT algorithm `24`, then send PSO `00 2A 9E 9A` with the hash.

### PSO COMPUTE DIGITAL SIGNATURE `00 2A 9E 9A Lc data` (D)

The data and response are the following:

- RSA: the data is a DigestInfo, or the raw hash for SHA-1 and SHA-256. The card adds the PKCS#1 v1.5 padding. The response is the signature (256 or 512 bytes, in several GET RESPONSE rounds).
- ECDSA: the data is the raw hash, truncated to the field size by the host. The response is r || s (56, 64, 96, or 132 bytes for P-224, P-256, P-384, P-521).

SM form: `0C 2A 9E 9A` with the hash in `81` (MAC only), after a plain MSE. On an RSA-2048 key EF whose crypto SCB requires SM, it works (V). The card returns the 256-byte signature encrypted, as one CBC ciphertext with padding indicator `00`. The ciphertext is split across two `87` objects: `87 FE 00 <253 bytes>` and `87 04 00 <3 bytes>`. The inner SW in the `99` object is `61 00`, although the whole signature is there. The card refuses the SM form with `69 87` on key EFs without SM in their crypto SCB, unless a DF SAE requires SM for INS `2A`. The SCBs of an EC key EF and an SAE on the EC key EF never make the card accept SM. Under a DF SAE `84 01 2A 9E 01 45`, ECDSA works only in the SM form (V): the plain form gets `69 82`, and the SM form returns the 64-byte P-256 signature in the SM response with inner SW `61 40`.

### PSO DECIPHER `00 2A 80 84 Lc cryptogram` (D)

RSA private key decipher after an MSE CT with algorithm `24` and `95 01 40`. RSA-4096 sends its 512-byte input with command chaining. The response is the plaintext with the PKCS#1 v1.5 padding removed.

SM form (V), on an RSA key EF whose crypto SCB requires SM:

- The cryptogram goes in blocks of at most 223 bytes. Each block is wrapped on its own: `87 E1 01 <224 bytes> 8E 04 MAC`, 233 bytes of SM data.
- CLA is `1C` on all blocks but the last, which has `0C`. The MAC header uses the CLA that is sent.
- The first block of a two-block cryptogram gets `61 0A` with a `99 02 90 00` response.
- The last block's response comes in two `87` objects (`87 FE 00 ..`, `87 04 00 ..`, padding indicator `00`, 256 bytes), with inner SW `61 00`.
- The 256 bytes are the PKCS#1 v1.5 block (`00 02 .. 00 <message>`). Under SM the card does not remove the padding.

The card refuses these other forms with `69 88` on the first block:

- BER-coded `87` lengths (`87 81 E1`)
- The MAC header over CLA `0C` on every block
- One SM data field for the whole cryptogram, split by ISO chaining

On key EFs without SM in their crypto SCB, the card refuses the SM form with `69 87`. RSA-4096 under SM sends its 512-byte cryptogram in three blocks (V).

### PSO ENCIPHER `00 2A 84 80 Lc data` (U)

RSA public key encipher after an MSE CT with `95 01 80`.

### PSO VERIFY DIGITAL SIGNATURE `00 2A 00 A8 Lc data` (N)

Verifies a signature. An MSE comes first. Success is `90 00`. Data longer than one block uses command chaining (CLA `10` on every block except the last). The layout of the data field is not known.

### PSO HASH `00 2A 90 80 Lc data` (N)

Computes a hash on the card. The MSE that comes first sets a hash template: `00 22 01 AA 03 80 01 <algo>`, with the algorithm references from the HT row of the algorithm table. The response is `61 XX` (XX = hash length, read with GET RESPONSE) or `90 00`. Data longer than one block uses command chaining (CLA `10` on every block except the last). The HT algorithm references in use are `80`, `82`, `84`, and `88` (SHA-1, SHA-256, SHA-384, SHA-512).

PSO COMPUTE DIGITAL SIGNATURE with Lc `00` (`00 2A 9E 9A 00`) signs the hash of the preceding PSO HASH.

### PSO COMPUTE CRYPTOGRAPHIC CHECKSUM `00 2A 8E 80 Lc data` (N)

Computes a MAC over the data with the key and algorithm of the CCT set by MSE. The response is `61 XX`, and GET RESPONSE returns the checksum.

Verified (V) with AES-CMAC: the MSE is `00 22 01 B4 08 80 01 1D 83 01 <key> 95 01 40`, and the PSO data is `80 L <data>`. The response is the full 16-byte AES-CMAC over the whole `80 L <data>` field, not truncated. With `84 00` instead of `83 01 <key>` in the CCT, the card computes the checksum under the session key, without secure messaging on the command.

A CT for a symmetric PSO ENCIPHER is not available: the MSE is accepted, but PSO ENCIPHER `00 2A 86 80` and `00 2A 84 80` return `6A 86`. The algorithm codes `04` and `06` of the older card are refused at MSE with `6A 80`.

Not verified (N): the data has `08` to `F8` bytes, a multiple of the block size, and longer data takes CLA `10` on all blocks but the last.

### PSO VERIFY CRYPTOGRAPHIC CHECKSUM `00 2A 00 A2 Lc 80 L data 8E L cc` (N)

Computes the checksum over the data in `80` and compares it with `8E`. Chained blocks (CLA `10`) carry only `80`. The last block carries the rest of the data, which may be empty, and `8E`. The card answers `90 00` on a match.

### PSO RECOVER SIGNED DATA `00 2A 90 9E Lc signature` (N)

Runs the RSA public key operation after an MSE DST. Removes the PKCS#1 v1.5 type 1 padding and returns the content (`61 XX`, GET RESPONSE). Bad padding gives `6A 80`. On the older card, RSA-2048 used two chained blocks of 128 bytes.

### Key agreement (unknown)

The functional specification does not list key agreement or ECDH as a card feature. It names a key agreement template (KAT, tag `A6`) in one sentence, with no layout and no command. The command layout for key agreement is not known, and nothing has been tested.

The driver has two unused hints:

- It defines the tag `A6` for the KAT, but the constant is commented out and marked as ACOS5-EVO only.
- Its algorithm table maps an MSE CT for EC to algorithm references `44`, `45`, and `46`, chosen by a length of 16, 24, or 32 bytes (U). This looks more like ECIES with an AES-128, AES-192, or AES-256 key than like plain ECDH.

The functional specification (section 4.7) stores templates as records in the SE file of a DF, so a KAT could live in an SE record. No command that runs the key derivation is known. The templates seen in SE records are AT `A4`, CCT `B4`, and CT `B8`. The templates seen in MSE SET are DST `B6`, CT `B8`, and HT `AA`.

ISO/IEC 7816-8 has two usual forms. Neither is confirmed for the ACOS5-EVO:

- MSE SET KAT `00 22 41 A6 Lc 80 01 <algo> 84 01 <key ref>` (or `81 02 <FID>`), then GENERAL AUTHENTICATE `00 86 00 00 Lc 7C L 85 L <peer public point>`. The response is `7C L 82 L <shared secret>`.
- PSO with the peer public point as data, the response being the X coordinate of the shared secret.

Do not probe for these on a card without a confirmed layout.

## Secure messaging

A command whose SCB is `4n` or `Cn` must be sent with the SM bits in CLA (`0C`, or `8C` for proprietary commands) and wrapped according to SE record n. The format with AES is verified (V):

1. GET CHALLENGE with 16 bytes gives the SSC. IV(command) = SSC+1, IV(response) = SSC+2, each a big-endian increment.
2. The command data objects are the following:
   - `97 01 Le`: expected length, for commands without data
   - `81 L data`: plain data, when the SE record has a CCT only
   - `87 L 01 E(data)`: encrypted data, AES-CBC with IV(command) and ISO padding, when the SE record has a CT
   - `8E 04 MAC`
3. The MAC is the first 4 bytes of AES-CMAC over `pad(89 04 CLA^0C INS P1 P2) || pad(DOs)`. The padding `80 00..` is added only if the length is not a multiple of 16. Each data object length L is one byte, also above `7F`. The card sends `87 FE ..` and accepts no BER forms.
4. The response is `[81 L data | 87 L 01 E(data)] 99 02 SW 8E 04 MAC`. The MAC covers everything before `8E`. Decrypt with IV(response).
5. The key is the static key from the SE record. The card uses no session keys here. The challenge is not part of the MAC, so commands with only a MAC can be replayed.
6. The card accepts SM only where the access condition requires it. It refuses an SM command to a file or DF whose SCB or SAE does not require SM with `69 87`. A driver mode that sends SM for every command therefore fails on such files.

READ BINARY and UPDATE BINARY are verified with MAC only and with MAC and encryption. The driver also wraps UPDATE RECORD, APPEND RECORD, and DELETE FILE (U).

Limits of the format:

- At most 240 bytes of plain data per command and per response (N). Verified (V): GET KEY under SM returns 224 bytes for Le `E0` and 240 bytes for Le `F0`, and is refused with `69 88` for Le `FF`. PSO DECIPHER works with 223 data bytes per block (233 bytes of SM data).
- Longer response data is split into several data objects (V: `87 FE` + `87 04` for a 256-byte result).
- The padding indicator `00` means no padding, `01` means padded (V: the card sends `00` for 256 bytes).
- The `99` object carries the SW of the plain command, for example `61 00` (V).
- On the ACOS5-EVO, VERIFY, CHANGE REFERENCE DATA, and RESET RETRY COUNTER work under SM (V). The card refuses SM for EC GENERATE KEY PAIR with `69 87` (V). It accepts SM for ECDSA signing only where a DF SAE requires SM for INS `2A` (V). Not verified on the ACOS5-EVO (N): SM for CREATE FILE, ERASE BINARY, ACTIVATE and DEACTIVATE FILE, TERMINATE DF and EF, MSE, and READ RECORD.

### Commands the driver sends under secure messaging

The following table lists the commands that the driver sends under SM. It sends them only where the card's access condition requires it. All rows are tested end to end through OpenSC (D):

| Command | SM form | When |
| --- | --- | --- |
| READ BINARY | `0C B0`, `97 01 Le` | The read SCB requires SM: the test files 4104 and 4105 (`--sm`), EF.ODF 5031, EF.TokenInfo 5032, and the PKCS#15 directory files 4110 to 4118 (`--bind`) |
| VERIFY (user PIN, ref `81`) | `0C 20 00 81`, encrypted `87` | `--bind` |
| CHANGE REFERENCE DATA (user PIN) | `0C 24 00 81`, encrypted `87` | `--bind` |
| RESET RETRY COUNTER (user PIN) | `0C 2C 00 81`, encrypted `87` | `--bind` |
| GENERATE KEY PAIR | `0C 46`, `81` (MAC only) | RSA key created with `+bound` |
| GET KEY (public key) | `8C CA`, `97 01 Le`, Le up to `E0` | RSA key created with `+bound` |
| PSO COMPUTE DIGITAL SIGNATURE | `0C 2A 9E 9A`, `81` | RSA key created with `+bound` |
| PSO DECIPHER | `1C 2A 80 84` for every block but the last, `0C 2A 80 84` for the last, each block of up to 223 bytes wrapped on its own | RSA key created or imported with `+bound` |
| PUT KEY | `8C DA`, encrypted `87` | RSA key imported with `+bound` |
| PSO COMPUTE DIGITAL SIGNATURE (RSA and ECDSA), GENERATE KEY PAIR (RSA) | `0C 2A 9E 9A` / `0C 46`, `81` (MAC only) | The DF SAE requires SM for INS `2A` / `46` (`--bind-sign`) |

These commands always stay plain:

- SELECT, MSE, GET CARD INFO, and GET CHALLENGE
- PSO DECIPHER with a key whose crypto SCB does not require SM
- The commands on EC keys, except on a card initialized with `--bind-sign`
- The SO PIN commands on the global PIN file (ref `01`, at the MF). The `--bind` SAE is on DF 4100 only, so mode `transmit` refuses the SO PIN commands.

PSO COMPUTE DIGITAL SIGNATURE with a `+bound` RSA key goes under SM on the driver's own signing path. That path takes a PKCS#1 v1.5 DigestInfo for SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 and sends the hash in `81`. Only SHA-256 is tested end to end. A DigestInfo for another digest algorithm takes the fallback through decipher: the driver adds the PKCS#1 v1.5 padding and sends PSO DECIPHER. For a `+bound` key, that PSO DECIPHER goes under SM, and the driver keeps the raw result. This fallback was tested with RIPEMD160-RSA-PKCS.

A `+bound` key has SCB `C2` for use and update, so the card refuses it in plain. After VERIFY under SM, MSE SET and PSO DECIPHER in plain on a `+bound` key return `69 82`. The same check returns `90 00` on a key with SCB `42`.

### Secure messaging with a static 3DES key (V)

Secure messaging also works with a 3DES-168 key. The SE record names the key and CCT algorithm `13`: `B4 09 83 01 <key> 95 01 30 80 01 13`. READ BINARY with a MAC on a file that such a record protects is verified.

The format is the AES format with 8-byte blocks:

- GET CHALLENGE with Le `08` gives the SSC.
- The command MAC is the first 4 bytes of 3DES-CBC with IV = SSC+1 over `pad(89 04 CLA^0C INS P1 P2) || pad(DOs)`, with the padding `80 00..` to a multiple of 8.
- The response MAC uses the same algorithm with IV = SSC+2, over everything before `8E`.

Unlike the AES MAC, the 3DES MAC depends on the challenge: the same command with IV = SSC gives `69 88`. A command sent again unchanged gets `69 88`, right after the original command and after a new GET CHALLENGE (V). So static 3DES SM commands cannot be replayed, unlike static AES SM commands.

The card refuses these forms with `69 88`:

- A 16-byte challenge, with its first or last 8 bytes plus 1 as the IV
- IV = SSC or SSC+2 for the command MAC
- ISO/IEC 9797-1 MAC algorithm 3 (retail MAC)
- Header and data objects padded together
- CCT algorithm `11` or `1D` with the same 3DES key

3DES encryption with a static key in a CT `B8` (algorithm `13`) works (V). An SM READ BINARY returns `87 L 00 <3DES-CBC(key, IV = SSC+2, data)>`, and an SM UPDATE BINARY sends `87` encrypted with IV = SSC+1, as for AES. The 3DES session key (CCT `84 00`) works too, see [3DES session key](#3des-session-key-v).

## GET CARD INFO `80 14 P1 P2 [Le]` (V)

The following table lists the sub-functions:

| P1 | P2 | Le | Returns |
| --- | --- | --- | --- |
| `00` | `00` | `08` | Serial number (8 bytes) |
| `01` | `00` | none | Number of files in the current DF, in SW2 (`90 NN`) |
| `02` | idx | `08` | File information of entry idx (1-based, 0 gives `6A 86`): `FDB 00 FID(2) size-or-MRL(2) NOR(2)` |
| `04` | `00` | `03` | Free EEPROM bytes (3 bytes) |
| `05` | `00` | none | Identify self, SW `95 C0` |
| `06` | `00` | `08` | COS version, `41 43 4F 53 05 04 32 C0` ("ACOS" 5.4) |
| `07` | `00` | `04` | Manufacture date on the ACOS5-64. The ACOS5-EVO returns "ACOS". |
| `08` | `00` | `14` | ROM SHA-1 on the ACOS5-64. The ACOS5-EVO answers `67 00`. |
| `09` | `00` | none | Operation mode in SW2 (`95 NN`), `95 01` = default, non-FIPS |
| `0A` | `00` | none | FIPS compliance check. `6F 56` in the non-FIPS mode. |
| `0B` | ref | none | PIN ref verified? (`90 00` yes) |
| `0C` | ref | none | Key ref authenticated? |

Not verified (N): on the older ACOS5, P1 `00` returned a 6-byte serial, and P1 `02` was 0-based with the entry `FDB DCB FID(2) size-or-MRL NOR SFI LCSI`. On the ACOS5-EVO the index is 1-based, with 2-byte MRL and NOR (V).

## Card life cycle and wipe

These commands wipe the card or change its life cycle.

### ZEROIZE CARD USER DATA `80 30 00 00 00` (V)

Deletes the whole file system. Allowed in the manufacturer stage and, unless the zeroize disable byte `C1 92` is set, in the personalization and user stages. It needs only the MF's delete self SCB, which the layout of `tools/evo_init.py` sets to `00`.

Not verified (N): a card that answers ZEROIZE with `6E 00` (class not supported) takes the older form `80 CA FF 00 00` instead. The ACOS5-EVO accepts `80 30`, so the older form does not apply to it.

> [!CAUTION]
> Both forms delete every file, PIN, and key on the card. You cannot recover any of them afterwards.

After ZEROIZE the card has no MF. Do not send UPDATE BINARY until the MF exists again: on the older ACOS5, UPDATE BINARY without an MF writes physical memory (N). `tools/safecard.py` refuses it.

### Lock commands (L, never send)

The following commands change the card's life cycle or header for good. `tools/safecard.py` refuses all of them:

| APDU | Effect |
| --- | --- |
| `80 12 00 00 00` | CHANGE LIFE CYCLE: manufacturer stage to transport stage, issuer stage, and so on |
| `80 10 00 00 08 code` | VERIFY TRANSPORT CODE (leave the transport stage) |
| `00 44 01 00 00` | ACTIVATE CARD: personalization stage to user stage. ZEROIZE is then no longer allowed. |
| `00 04 01 00 00` | DEACTIVATE CARD |
| `00 D6 C1 92 01 00` / `00 D6 C1 92 01 FF` | Writes the zeroize disable byte: `00` allows ZEROIZE, `FF` disables it |
| `00 D6 C1 91 01 mode` | Writes the operation mode byte (`01` = default, non-FIPS). The read form is `00 B0 C1 91 01`. |
| `80 32 <old TA1> <new TA1> 00` | SET BAUD RATE (N): rewrites TA1 of the ATR. The MF must be current. |

The functional specification lists these life cycle stages: manufacturer (all commands), transport, issuer, personalization, user (activated) and deactivated, and terminated (DELETE only). A card set up with `tools/evo_init.py` stays in the manufacturer stage.
