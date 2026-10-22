# Card content rules

The driver works only with a card file system that follows PKCS#15 (ISO/IEC 7816-15), OpenSC's conventions, and a few rules of the driver. A card initialized with the tools of this repository follows these rules. The rules matter when you change the card with other tools, for example `gscriptor` or `scriptor`.

If the card content breaks a rule, the driver can stop with an error or abort the program. Run `pkcs15-init --sanity-check` to find such problems.

## File access

OpenSC needs to read some files without a PIN:

- EF.DIR, EF.ODF, EF.TokenInfo, and every file that EF.ODF points to
- Every security environment (SE) file. The driver reads the SE files to learn how to verify PINs.

A read condition that needs secure messaging, but no PIN, is allowed. A card bound with `tools/evo_init.py --bind` uses that for its PKCS#15 files.

A card that ACS software initialized often allows reading its SE files only after a PIN, which this driver cannot handle. Initialize such a card again. See [Initialize a card](../guides/initialize-a-card.md).

## File IDs

The driver uses the following file IDs:

- `5000` to `5FFF` hold the key files. The driver creates RSA key files there, and on the ACOS5-EVO also EC key files. It allocates them in pairs.
- `5031`, `5032`, and `5033` are the PKCS#15 files EF.ODF, EF.TokenInfo, and EF.UnusedSpace.

> [!CAUTION]
> Do not put other files in the range `5000` to `5FFF`. The driver can delete any file of another type there, and any key file that the PKCS#15 key directories do not list.

A file path can have at most 16 bytes, which is eight file IDs including the MF. OpenSC cannot handle longer paths.

## Record files

PIN files, symmetric key files, and SE files hold records. Each record stores an ID: the PIN reference, the key ID, or the SE ID. The record number and the ID inside the record must be equal. The driver can check that only in files it can read, and PIN files and key files are never readable.

A symmetric key that the PKCS#15 secret key directory (EF.SKDF) does not list does not exist for OpenSC. The driver overwrites its record the next time it stores or unwraps a key. List every key you add by hand in EF.SKDF.

## PKCS#15 ASN.1 content

The PKCS#15 files must contain ASN.1 that OpenSC and the driver accept. The module [PKCS15.asn](https://github.com/carblue/acos5_gui/blob/master/source/PKCS15.asn) describes it. It is the PKCS#15 v1.1 module, changed for OpenSC, Libtasn1, and the ACOS5. The driver uses it internally on Linux and other systems except Windows.

## Layout of an initialized ACOS5-EVO

The following table shows the file system that `tools/evo_init.py` creates:

| File | ID | Content |
| --- | --- | --- |
| MF | `3F00` | The root directory. Its SE file is `0003`. |
| Global PIN file | `3F00/0001` | The SO PIN and SO PUK, reference `01` |
| Global SE file | `3F00/0003` | SE record 1: SO PIN |
| EF.DIR | `3F00/2F00` | One application with the AID `ACOSPKCS-15v1.00` and the path `3F00/4100` |
| Application directory | `3F00/4100` | The PKCS#15 application. Its SE file is `4103`. |
| Local PIN file | `4100/4101` | The user PIN and user PUK, reference `81` |
| Local symmetric key file | `4100/4102` | With `--sm`: key `81` (host authentication) and key `82` (secure messaging), both AES-192. The keys are never readable and never usable for encryption or decryption commands. |
| Local SE file | `4100/4103` | SE records 1 to 6, described in the next table |
| Secure messaging test files | `4100/4104`, `4100/4105` | With `--sm`: 16-byte files that need secure messaging to read |
| PKCS#15 directory files | `4100/4110` to `4100/4118` | PrKDF, PuKDF, PuKDF trusted, SKDF, CDF, CDF trusted, CDF useful, DODF, AODF |
| EF.ODF | `4100/5031` | Points to the PKCS#15 directory files |
| EF.TokenInfo | `4100/5032` | Serial number and label. It lists no supported algorithms. |

The local SE file `4103` holds the following records. The access conditions of files and keys refer to them by number:

| SE record | Condition |
| --- | --- |
| 1 | User PIN |
| 2 | User PIN, and secure messaging with MAC and encryption |
| 3 | SO PIN |
| 4 | User PIN and SO PIN |
| 5 | Secure messaging with MAC |
| 6 | Secure messaging with MAC and encryption |

With `--bind`, the application directory `4100` has security attributes that require secure messaging with MAC and encryption for the user PIN commands. With `--bind-sign`, they also require secure messaging with a MAC for PSO commands (signing, decryption) and for GENERATE KEY PAIR.

The PKCS#15 directory files and EF.ODF and EF.TokenInfo need no PIN to read or write. With `--bind`, reading them needs secure messaging with a MAC. The certificate directory file `4114` holds 6 KB, because the driver stores certificates inside it.

The card stays in its manufacturer stage. In that stage the card enforces all access conditions, and the MF can always be deleted. You can therefore always wipe and initialize the card again.
