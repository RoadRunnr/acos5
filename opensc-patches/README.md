# OpenSC source patches for the ACOS5-EVO

Two small OpenSC fixes make the ACOS5-EVO work fully. Both are submitted upstream; apply them to the OpenSC source before building until they are in a release. Each is a plain `git diff` against OpenSC master and applies with `git apply` or `patch -p1` from the OpenSC source root.

| Patch | What it fixes | Upstream |
| --- | --- | --- |
| `pkcs15-ec-read_public_key-spki.patch` | OpenSC drops the curve of an EC public key that a driver returns as an SPKI, so PKCS#11 shows EC keys without their parameters and applications cannot use them. The patch keeps the curve. | [OpenSC#3884](https://github.com/OpenSC/OpenSC/pull/3884) |
| `apdu-case4-short-no-le.patch` | The ACOS5-EVO answers `67 00` to a short case 4 APDU that carries Le under T=1. The patch adds the card capability `SC_CARD_CAP_CASE4_SHORT_NO_LE`; a card with it set gets such APDUs sent without Le, as under T=0. The driver sets the capability, so the card works on the contact interface without forcing T=0, and over the contactless interface, where T=0 is not available. | pending |

Without `pkcs15-ec-read_public_key-spki.patch`, RSA keys still work; EC keys do not.

Without `apdu-case4-short-no-le.patch`, force T=0 for the contact interface with a `card_atr` block in `opensc.conf` (see the configuration reference). Contactless then does not work, because T=0 cannot be negotiated over the RF interface.

## Applying

```bash
cd OpenSC
for p in /path/to/acos5/opensc-patches/*.patch; do git apply "$p"; done
# then build OpenSC as usual
```

For a Debian or Ubuntu package rebuild, append the patch file names to `debian/patches/series` and place the files in `debian/patches/`.
