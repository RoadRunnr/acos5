# acos5_pkcs15

`acos5_pkcs15` is the PKCS#15 initialization (pkcs15init) module of the acos5 driver, built as `libacos5_pkcs15.so`. OpenSC loads it for every operation that writes to the card, for example key generation, key import, and certificate storage. It needs the profile file `acos5_external.profile` from this directory.

For the build, the installation, and the `opensc.conf` entries, see [Installation](../docs/installation.md).
