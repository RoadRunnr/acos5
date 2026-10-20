# Build options

The build scripts `build.rs` set compile-time options for the driver. Each option is a line of the following form:

```rust
println!("cargo:rustc-cfg={OPTION}");
```

A line is active when it is not commented out. To change an option, edit the line, then rebuild the driver. The options for the card driver are in `acos5/build.rs`. The file `acos5_pkcs15/build.rs` has the same content, so change both files the same way.

## Options for the driver

The following table lists the options in `acos5/build.rs` and `acos5_pkcs15/build.rs`:

| Option | Active by default | Description |
| --- | --- | --- |
| `log` | Yes | Writes the driver's messages to the OpenSC debug log when `debug` is greater than 0 in `opensc.conf`. Without it, the driver logs almost nothing. |
| `enforce_restricted_op_mode_byte` | Yes | Refuses cards in an unsupported configuration mode. See [Supported cards](supported-cards.md#configuration-mode). |
| `iup_user_consent` | No | Shows a dialog before each use of an RSA private key. See [User consent dialog](#user-consent-dialog). |
| `ifd_serial_constrained_for_sm` | No | Uses secure messaging only with the card whose serial number is in the `ifd_serial` setting of `opensc.conf`. Useful only if you have one card with secure messaging. For an ACOS5-64 V2.00 with its 6-byte serial number, add two zero bytes. |
| `key_gen_verbose` | No | Prints information to the console during key pair generation. |
| `finish_verbose` | No | Prints information to the console when the driver finishes. |
| `dev_relax_signature_constraints_for_raw` | No | Relaxes checks for raw RSA signatures. This setting is insecure. Do not use it. |

## User consent dialog

With the option `iup_user_consent`, the driver opens a dialog every time a program uses an RSA private key to sign, decrypt, or unwrap. Answer **No** to refuse the use of the key. **Yes** or closing the window allows it. The dialog uses the [IUP](https://webserver2.tecgraf.puc-rio.br/iup/) toolkit.

1. Install IUP, for example from the [prebuilt binaries](https://sourceforge.net/projects/iup/files/). On Linux, run the `install` script of the package, then check the dependencies with `ldd libiup.so`.
2. In `acos5/build.rs` and `acos5_pkcs15/build.rs`, activate the line for `iup_user_consent`.
3. Activate the two lines after it, which link `libiup` and name its directory. Adapt the directory to your system.
4. Rebuild and install the driver.
5. In the `card_driver acos5_external` block of `opensc.conf`, set `iup_user_consent_enabled = yes;`.

With `iup_user_consent_enabled = no;`, the dialog stays off without a rebuild. That helps for tests that use many keys, for example `pkcs11-tool --test`.

## The OpenSC binding

The crate `opensc-sys` is the Rust binding to `libopensc`. Its build script detects the version of the installed OpenSC and activates one version option, for example `v0_27_1`. It refuses versions older than 0.20.0. The binding then matches the data structures of that OpenSC version.

The binding assumes that OpenSC was built with the same settings as the Debian package for x86_64, in particular these two:

- `ENABLE_OPENSSL`, OpenSSL support
- `ENABLE_SM`, secure messaging support

If you build OpenSC with other settings, adapt the binding first. The following commands build OpenSC with settings that fit the binding:

```bash
tar xfz opensc-{VERSION}.tar.gz
cd opensc-{VERSION}
./bootstrap
./configure --prefix=/usr --sysconfdir=/etc/opensc --libdir=/usr/lib/x86_64-linux-gnu
make
sudo make install
```

The `libdir` differs on some systems.

The script `opensc-sys/build.rs` also sets four options that the driver needs: `impl_default`, `impl_display`, `acos5_impl_default`, and `impl_newAT_newCCT_newCT`. Do not change them.

## Libraries to link

The build scripts link OpenSSL (`libcrypto`) and Libtasn1. On systems other than Debian and Ubuntu, check the lines that start with `println!("cargo:rustc-link` in the three `build.rs` files. If a library has another name or is outside the linker's search path, adapt the name or add a line of the following form:

```rust
println!("cargo:rustc-link-search=native={LIBRARY_DIRECTORY}");
```

## API documentation

The source code has Rust documentation comments, especially for the OpenSC binding. Run the following command to build the documentation and open it in a browser:

```bash
cargo doc --open --document-private-items
```

The documentation goes to `target/doc/`.
