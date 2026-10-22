# Troubleshooting

This page lists common problems with the driver and how to find their cause. Most problems show up in the OpenSC debug log first.

## Turn on the debug log

1. Add the following lines to the `app default` block of `opensc.conf`:

   ```text
   debug = 3;
   debug_file = /tmp/opensc-debug.log;
   ```

2. Run the command that fails.

3. Read the log file.

Remove the two lines when you are done. The log can hold data that goes to and from the card.

When OpenSC loads the driver, the first lines of the log contain `successfully loaded card driver 'acos5_external'`. Commands that write to the card also load the pkcs15init module and log `successfully loaded pkcs15init driver 'acos5_external'`.

## OpenSC does not load the driver

`opensc-tool --name` shows another driver's name, or the log has no line `successfully loaded card driver 'acos5_external'`. Check the following:

- The `module` path in the `card_driver acos5_external` block points to `libacos5.so`.
- `acos5_external` is the first entry of the `card_drivers` list.
- The driver was built for the installed OpenSC version. OpenSC refuses a driver built for another version. Rebuild the driver after every OpenSC update. See [Installation](installation.md#build-the-driver).
- An OpenSC update did not overwrite `opensc.conf`. Compare the file with your backup.

If the build fails, run the binding test:

```bash
cargo test --release -p opensc-sys test_struct_sizeof -- --nocapture
```

The test fails in the following cases:

- The linker does not find `libopensc.so`.
- The OpenSC version differs from the version that `opensc-tool --info` reports.
- OpenSC was built with other settings than the binding expects.

For the OpenSC build settings, see [Build options](reference/build-options.md#the-opensc-binding).

## No reader found

`opensc-tool --list-readers` shows no reader. Check that `pcscd` runs and that your user may use it. Over SSH, and in sessions outside the local desktop session, polkit can deny access. The `pcscd` log then contains `not authorized for action: access_pcsc`. A polkit rule that allows the actions `org.debian.pcsc-lite.access_pcsc` and `org.debian.pcsc-lite.access_card` for your user fixes that.

## ACOS5-EVO commands fail with status 6700

Under protocol T=1, the ACOS5-EVO rejects many commands with status `67 00`. Add the `card_atr` block with `force_protocol = "t0"` to `opensc.conf`. See [Configuration reference](reference/configuration.md#the-card_atr-block-for-the-acos5-evo).

## EC keys have no curve

PKCS#11 applications cannot use EC keys from an ACOS5-EVO, and `pkcs11-tool --list-objects` shows the keys without EC parameters. OpenSC lacks the fix from [OpenSC pull request #3884](https://github.com/OpenSC/OpenSC/pull/3884). Build OpenSC with that fix.

## Secure messaging errors

On an ACOS5-EVO with secure messaging, the driver logs the cause of an error in a line that contains `secure_messaging: card {SERIAL}`. The following table lists the messages and what to do:

| Log message | Fix |
| --- | --- |
| `the access condition requires SM, but mode is none; set mode` | Set `mode = acl;` for the card. |
| `SM is required, but no keys are set; set a keyset or kmc` | Add the card's keyset or a master key to the `secure_messaging` block. |
| `mode transmit refused a PIN or key command without encryption` | The command would send a PIN or key in plain text, because the card does not require encryption for it. Use mode `acl` for this card. SO PIN commands always fail in mode `transmit`. |
| `PSO DECIPHER under SM needs an SE record with a CT (encryption)` | The key's access condition requires secure messaging without encryption. Create the key with the profile option `+bound`. |
| `no block named {NAME}` | The `secure_messaging` setting in `card_driver` names a block that does not exist. |
| `invalid setting for card {SERIAL}` | A mode, key, or master key value is invalid. Keys have 48 hexadecimal digits, a master key has 64. |

The line `secure_messaging: card {SERIAL}, mode {MODE}, keys from {SOURCE}` shows the settings that the driver uses for the card. If the keys in `opensc.conf` differ from the keys on the card, the card rejects the protected commands. A bound card then refuses to show its PINs and keys. Copy the keys again from `~/.config/acos5evo/{SERIAL}.conf`. Without the right keys, the only recovery is to wipe and initialize the card.

Some secure messaging messages for PIN commands appear only with `debug = 9;`.

## The driver aborts the program

The driver stops with an error, or the program aborts with a message about a failed assertion. This usually means the card content breaks a rule that the driver expects. Run the following command to check the card content:

```bash
pkcs15-init --sanity-check
```

For the rules, see [Card content rules](reference/card-content-rules.md). A card that ACS software initialized usually needs a new initialization. See [Initialize a card](guides/initialize-a-card.md).

## A CryptoMate EVO stops working

A CryptoMate EVO USB token sometimes stopped working in tests and needed a reset. The cause is unknown. An ACOS5-EVO smart card with T=0 in a CCID reader showed no such problem. If you see this behavior, a report with the debug log helps to find the cause.

## Report a problem

If none of these steps helps, open an issue in the repository. Add the OpenSC version, the card type, the command you ran, and the relevant part of the debug log. Remove PINs and keys from the log first.
