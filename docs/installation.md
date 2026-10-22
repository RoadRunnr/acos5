# Installation

The acos5 driver is a pair of external modules for OpenSC. You build both modules from source with Cargo, then register them in `opensc.conf`. This page covers Debian and Ubuntu. Other Linux distributions work the same way with their own package names.

The two modules are:

- `libacos5.so`, the card driver. OpenSC loads it as the card driver `acos5_external`.
- `libacos5_pkcs15.so`, the PKCS#15 initialization (pkcs15init) module. You need it for every operation that writes to the card, for example key generation, key import, and certificate storage.

## Prerequisites

Before you begin, make sure you have the following:

- OpenSC 0.20.0 or later, up to 0.27.1, with the PKCS#11 module `opensc-pkcs11.so`
- [Rust](https://www.rust-lang.org/tools/install) with `cargo`, from rustup or from your distribution
- The development files of OpenSSL and [Libtasn1](https://www.gnu.org/software/libtasn1/)
- `pcscd` with a CCID reader driver. The `ccid` package of your distribution supports the ACS tokens if it lists them on the [supported readers page](https://ccid.apdu.fr/ccid/shouldwork.html). You do not need the ACS driver `acsccid`.
- A card in a supported configuration mode. See [Supported cards](reference/supported-cards.md).

The following command installs these packages on Debian and Ubuntu:

```bash
sudo apt install opensc opensc-pkcs11 openssl libssl-dev libtasn1-6-dev pcscd build-essential cargo pcsc-tools
```

The `pcsc-tools` package has `scriptor`, which initializes the ACOS5-64 V2.00 and V3.00. For an ACOS5-EVO, also install the Python modules that the initialization tool needs:

```bash
sudo apt install python3-pyscard python3-cryptography
```

The paths on this page are for x86_64. On other architectures, Debian and Ubuntu use another directory instead of `x86_64-linux-gnu`, for example `aarch64-linux-gnu`.

> [!IMPORTANT]
> On the ACOS5-EVO, two small OpenSC source patches are not yet in a release. Apply them to the OpenSC source before building it; see [opensc-patches](../opensc-patches/README.md). `pkcs15-ec-read_public_key-spki.patch` ([OpenSC#3884](https://github.com/OpenSC/OpenSC/pull/3884)) is needed for EC keys, or PKCS#11 shows them without their curve and applications cannot use them; RSA keys work without it. `apdu-case4-short-no-le.patch` lets the card work without forcing T=0 and enables the contactless interface; without it, force T=0 for the contact interface as the configuration reference describes.

## Build the driver

The build links against the OpenSC library that is installed on your system. It detects the OpenSC version and builds the driver for exactly that version.

1. Check that the linker finds `libopensc.so`:

   ```bash
   ls -l /usr/lib/x86_64-linux-gnu/libopensc.so
   ```

   Distributions often ship only the versioned file, for example `libopensc.so.13`.

2. If the unversioned link is missing, create it:

   ```bash
   sudo ln -s libopensc.so.{SONAME_VERSION} /usr/lib/x86_64-linux-gnu/libopensc.so
   ```

3. Clone the repository and build both modules:

   ```bash
   git clone https://github.com/carblue/acos5.git
   cd acos5
   cargo build --release
   ```

4. Test that the binding matches the installed OpenSC:

   ```bash
   cargo test --release -p opensc-sys test_struct_sizeof -- --nocapture
   ```

The build writes `libacos5.so` and `libacos5_pkcs15.so` to `target/release/`. The test prints the version of the installed OpenSC and ends with `test result: ok`.

> [!IMPORTANT]
> OpenSC loads the driver only if the driver was built for the installed OpenSC version. Rebuild the driver after every OpenSC update. Delete the `target` directory and `Cargo.lock` first, so that the build detects the new version.

For compile-time options, such as the user consent dialog, see [Build options](reference/build-options.md).

## Install the modules

You can load the modules from any directory. This page uses `/usr/local/lib/acos5_external/`.

1. Copy both modules:

   ```bash
   sudo install -d /usr/local/lib/acos5_external
   sudo install -m 0644 target/release/libacos5.so target/release/libacos5_pkcs15.so /usr/local/lib/acos5_external/
   ```

2. Copy the profile to the directory with the other OpenSC profiles:

   ```bash
   sudo install -m 0644 acos5_pkcs15/acos5_external.profile /usr/share/opensc/
   ```

On some systems the OpenSC profiles are in `/usr/local/share/opensc/` instead. Use the directory that contains `pkcs15.profile`.

## Register the driver in opensc.conf

OpenSC reads its configuration from `/etc/opensc/opensc.conf`. Add the driver, the pkcs15init module, and for the ACOS5-EVO the protocol setting to the `app default` block.

> [!CAUTION]
> Back up `opensc.conf` before you change it. Some OpenSC packages overwrite the file on upgrade.

The following snippet shows the minimal configuration. Keep the other content of your `app default` block:

```text
app default {
    ...
    card_driver acos5_external {
        module = /usr/local/lib/acos5_external/libacos5.so;
    }
    card_drivers = acos5_external, internal;

    # ACOS5-EVO only: use protocol T=0
    card_atr 3B:9E:96:80:01:41:05:43:00:00:00:00:00:00:00:00:00:90:00:1E {
        atrmask = "FF:FF:FF:FF:FF:FF:FF:F0:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00";
        force_protocol = "t0";
    }

    framework pkcs15 {
        ...
        pkcs15init acos5_external {
            module = /usr/local/lib/acos5_external/libacos5_pkcs15.so;
        }
    }
}
```

The `card_drivers` line puts `acos5_external` before the drivers that are built into OpenSC. The ACOS5-EVO needs protocol T=0. For the reason, see [Supported cards](reference/supported-cards.md#protocol-t0-on-the-acos5-evo).

For all settings, including secure messaging, see [Configuration reference](reference/configuration.md).

## Verification

Insert the card and run the following command to check that OpenSC uses the driver:

```bash
opensc-tool --name
```

For an ACOS5-EVO, the command prints the driver's name for the card:

```text
Using reader with a card: {READER_NAME}
ACOS5-EVO V4.X0: Smart Card EVO or CryptoMate EVO
```

A new card has no PKCS#15 file system yet. Initialize it before you use it with PKCS#11 applications. See [Initialize a card](guides/initialize-a-card.md).

> [!NOTE]
> If OpenSC does not load the driver, see [Troubleshooting](troubleshooting.md).
