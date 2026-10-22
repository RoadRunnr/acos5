# acos5

acos5 is an open-source driver for the ACOS5 smart cards and USB tokens from Advanced Card Systems (ACS). It plugs into [OpenSC](https://github.com/OpenSC/OpenSC/wiki) as an external module. Through OpenSC's PKCS#11 module, applications such as OpenSSH, OpenSSL, Firefox, and Thunderbird can then use keys on the card.

ACS offers no open-source PKCS#11 library for these cards, and OpenSC 0.27.1 has no driver for them.

## Supported cards

The driver supports the following cards:

- ACOS5-64 V2.00, sold as the CryptoMate64 USB token
- ACOS5-64 V3.00, sold as the CryptoMate Nano USB token
- ACOS5-EVO V4.X0, sold as a smart card and as the CryptoMate EVO USB token

It works with OpenSC 0.20.0 to 0.27.1. For the configuration modes and the tested features of each card, see [Supported cards](docs/reference/supported-cards.md).

## Features

The driver offers these functions through PKCS#11 and the OpenSC tools:

- RSA keys from 512 to 4096 bits: generation on the card, import, signing, and decryption
- EC keys on the ACOS5-EVO (P-224, P-256, P-384, P-521): generation on the card, import, and ECDSA signing
- Certificates, PIN change and unblock, and key deletion
- Secure messaging with AES keys on the ACOS5-EVO, with keys and PINs bound to the hosts that hold the keys
- A content check with `pkcs15-init --sanity-check`

## Quick start

The following steps set up an ACOS5-EVO without secure messaging on Debian or Ubuntu. Each step links to the full guide.

1. Install the packages, build the driver, install it, and register it in `opensc.conf`. Follow [Installation](docs/installation.md). The build part is the following:

   ```bash
   git clone https://github.com/carblue/acos5.git
   cd acos5
   cargo build --release
   sudo install -d /usr/local/lib/acos5_external
   sudo install -m 0644 target/release/libacos5.so target/release/libacos5_pkcs15.so /usr/local/lib/acos5_external/
   sudo install -m 0644 acos5_pkcs15/acos5_external.profile /usr/share/opensc/
   ```

2. Initialize the card. See [Initialize a card](docs/guides/initialize-a-card.md).

   > [!CAUTION]
   > Initialization deletes everything on the card.

   ```bash
   python3 tools/evo_init.py --user-pin {USER_PIN} --user-puk {USER_PUK} --so-pin {SO_PIN} --so-puk {SO_PUK}
   ```

3. Generate a key pair on the card. See [Manage keys and certificates](docs/guides/manage-keys-and-certificates.md).

   ```bash
   pkcs15-init --generate-key rsa/2048 --auth-id 01 --id 01 --label ssh-key --key-usage sign
   ```

   EC keys need an OpenSC fix that is not yet released. See [Installation](docs/installation.md#prerequisites).

4. Use the key with OpenSSH. See [Use the card with applications](docs/guides/use-with-applications.md).

   ```bash
   ssh-keygen -D /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
   ssh -I /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so {USER}@{HOST}
   ```

For an ACOS5-64 V2.00 or V3.00, use the initialization script in [`info/card_initialization`](info/card_initialization/README.md) in step 2. For secure messaging on an ACOS5-EVO, follow [Set up secure messaging](docs/guides/set-up-secure-messaging.md) before step 3.

## Documentation

The documentation is in the `docs` directory:

| Section | Pages |
| --- | --- |
| Concepts | [Secure messaging](docs/concepts/secure-messaging.md) |
| Installation | [Installation](docs/installation.md) |
| Guides | [Initialize a card](docs/guides/initialize-a-card.md), [Manage PINs](docs/guides/manage-pins.md), [Manage keys and certificates](docs/guides/manage-keys-and-certificates.md), [Set up secure messaging](docs/guides/set-up-secure-messaging.md), [Use the card with applications](docs/guides/use-with-applications.md) |
| Troubleshooting | [Troubleshooting](docs/troubleshooting.md) |
| Technical reference | [Configuration reference](docs/reference/configuration.md), [Supported cards](docs/reference/supported-cards.md), [Card content rules](docs/reference/card-content-rules.md), [Build options](docs/reference/build-options.md), [ACOS5-EVO command reference](docs/reference/acos5-evo-commands.md) (for driver developers) |

## Repository content

The repository holds the following parts:

| Directory | Content |
| --- | --- |
| `acos5` | The card driver, built as `libacos5.so`. OpenSC knows it as `acos5_external`. |
| `acos5_pkcs15` | The PKCS#15 initialization module `libacos5_pkcs15.so` and its profile `acos5_external.profile`. Needed for every operation that writes to the card. |
| `opensc-sys` | The Rust binding to `libopensc`, with bindings to Libtasn1 and some OpenSSL functions |
| `tools` | The ACOS5-EVO initialization tool and its helpers. See [`tools/README.md`](tools/README.md). |
| `info` | Initialization scripts for the ACOS5-64 V2.00 and V3.00, and background notes |
| `project_pkcs11_example_apps` | Example programs that use the card through PKCS#11 |

The driver is written in Rust. Both modules are tied to the OpenSC version they were built for. Rebuild them after every OpenSC update.

## Further reading

These external pages explain smart cards and certificates on Linux in general:

- [Linux and smart cards for PKI: overview](http://cedric.dufour.name/blah/IT/SmartCardsOverview.html)
- [Linux and smart cards with OpenSC: how-to](http://cedric.dufour.name/blah/IT/SmartCardsHowto.html)
- [OpenSSL certificate authority](https://jamielinux.com/docs/openssl-certificate-authority/), with changes in `info/howto/HOWTO_Create_Your_own_CA_root_hierarchy_on_Linux`

## License

See [LICENSE](LICENSE).
