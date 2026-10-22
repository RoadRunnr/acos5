# Supported cards

The driver supports three generations of the Advanced Card Systems (ACS) ACOS5 card. Each generation exists as a smart card and as a USB token:

| Card | USB token | Configuration mode supported |
| --- | --- | --- |
| ACOS5-64 V2.00 | [CryptoMate64](https://www.acs.com.hk/en/products/18/cryptomate64-usb-cryptographic-tokens/) | `00`, the ACOS5-64 mode |
| ACOS5-64 V3.00 | [CryptoMate Nano](https://www.acs.com.hk/en/products/414/cryptomate-nano-cryptographic-usb-tokens/) | `02`, the 64K mode |
| ACOS5-EVO V4.X0 | [CryptoMate EVO](https://www.acs.com.hk/en/products/494/cryptomate-evo-cryptographic-usb-tokens/) | `01`, the default non-FIPS mode |

The driver does not support the older ACOS5-32 V1.00.

## Configuration mode

Each card has a configuration mode byte in its header at address `C191`. You can change the byte only while the card is new. The driver works only in the modes the previous table lists:

- On the ACOS5-64 V2.00, any other value starts the ACOS5-32 compatibility mode. The card has no command to read the byte, so make sure it is `00`.
- On the ACOS5-64 V3.00, the driver refuses the emulated 32K mode (`01`). The NSH-1 mode and the FIPS 140-2 mode are untested.
- On the ACOS5-EVO, the driver accepts only the mode bytes `00` and `01`. Only `01` is tested. The FIPS 140-2 mode is untested.

## Features of the ACOS5-EVO

The following features were tested with an ACOS5-EVO smart card in a CCID reader with OpenSC 0.27.1:

- RSA key generation, signing, and decryption with 2048-bit and 4096-bit keys
- EC key generation and ECDSA signing for P-224, P-256, P-384, and P-521
- Private key import for RSA-2048 and EC P-256 keys
- Certificates, PIN change and unblock, key deletion, and `pkcs15-init --sanity-check`
- Secure messaging with AES keys, including PIN commands, RSA keys bound to secure messaging, and signing bound to secure messaging for all keys (`--bind-sign`)
- OpenSSH with `ssh-agent`, the OpenSSL `pkcs11-provider`, and NSS

The driver does not support these functions on the ACOS5-EVO:

- Key agreement (ECDH). EC keys can only sign.
- Hashing, CMAC, and AES encryption on the card through PKCS#11
- The FIPS 140-2 configuration mode

For EC keys, OpenSC needs the fix from [OpenSC pull request #3884](https://github.com/OpenSC/OpenSC/pull/3884). The ACOS5-EVO keeps public keys in key files that only the driver can read. The driver returns an EC public key with its curve, and OpenSC 0.27.1 drops the curve without the fix. PKCS#11 then shows EC keys without their parameters, and applications cannot use them.

## Protocol T=0 on the ACOS5-EVO

The ACOS5-EVO starts with protocol T=1. A command that sends data and expects data back is an ISO/IEC 7816-4 case 4 command. Under T=1, the card rejects every case 4 command that carries the expected-length byte (Le). It answers status `67 00`. This affects, for example, SELECT with file control information, secure messaging, and signing. The card accepts these commands only without Le. It then answers `61 XX`, and the response data follows with GET RESPONSE.

ISO/IEC 7816-3:2006, clause 12.3.5, says that under T=1 the command goes to the card unchanged, Le included. OpenSC follows the standard. Under T=0 (clause 12.2.5) the reader drops Le, and the card works as the standard says. So configure OpenSC to use T=0 for the ACOS5-EVO. See [Configuration reference](configuration.md#the-card_atr-block-for-the-acos5-evo).

Under T=0 the driver uses no extended commands. It sends long data, for example for RSA-4096 decryption, in several chained commands, and it reads long responses with GET RESPONSE.

The file `diff_apdu_c.txt` patches OpenSC for T=1 instead. That patch is not recommended: it changes the handling of case 4 commands for all cards, not only for the ACOS5-EVO.

> [!NOTE]
> A CryptoMate EVO USB token sometimes stopped working in tests. See [Troubleshooting](../troubleshooting.md#a-cryptomate-evo-stops-working).

## OpenSC versions and platforms

The driver supports OpenSC 0.20.0 to 0.27.1. It is tested only with the latest supported version, so install that version.

The driver builds on the platforms that the Rust compiler supports. It is tested on Linux, mainly Kubuntu 24.04 LTS. On Windows 11, only read operations worked in tests. Secure messaging and everything that needs `libacos5_pkcs15` failed, because the driver could not read `opensc.conf` and the profile files.

## Card references

ACS gives the reference manual for each card on request at info@acs.com.hk. ACS publishes the functional specification of the ACOS5-EVO.
