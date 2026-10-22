# Configuration reference

The driver reads its settings from the OpenSC configuration file `opensc.conf`, inside the `app default` block. On Linux the file is `/etc/opensc/opensc.conf`. On Windows it is `C:\Program Files\OpenSC Project\OpenSC\opensc.conf`.

The following example shows a complete configuration for one ACOS5-EVO with secure messaging. The `...` lines stand for the other content of the file:

```text
app default {
    ...
    card_driver acos5_external {
        module = /usr/local/lib/acos5_external/libacos5.so;
        secure_messaging = acos5_evo;
    }
    secure_messaging acos5_evo {
        mode = none;
        card {SERIAL} {
            mode = acl;
            keyset_41434F53504B43532D313576312E3030_02_enc = "{KEY_82_HEX}";
            keyset_41434F53504B43532D313576312E3030_02_mac = "{KEY_81_HEX}";
        }
    }
    card_drivers = acos5_external, internal;

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

## The card_driver block

The `card_driver acos5_external` block registers the card driver. The following table lists its settings:

| Setting | Required | Description | Default value |
| --- | --- | --- | --- |
| **module** | Yes | The path of `libacos5.so`. A file name without a path works if the file is in the library search path. | none |
| **secure_messaging** | No | The name of the `secure_messaging` block that holds the ACOS5-EVO secure messaging settings. Never put this setting into a `card_atr` block: OpenSC then tries to load an external secure messaging module, and the card setup fails. | none |
| **ifd_serial** | No | The serial number of the only card that may use secure messaging, as 8 bytes in hexadecimal separated by colons. Takes effect only if the driver was built with the option `ifd_serial_constrained_for_sm`. Otherwise keep the value `"11:22:33:44:55:66:77:88"` or leave the setting out. | `"11:22:33:44:55:66:77:88"` |
| **iup_user_consent_enabled** | No | `yes` shows a confirmation dialog before each use of an RSA private key, `no` turns the dialog off. Takes effect only if the driver was built with the option `iup_user_consent`. | `yes` in such a build |
| **keyset_{AID}_02_enc**, **keyset_{AID}_02_mac** | No | Deprecated secure messaging keys. The driver reads them only if the block has no `secure_messaging` setting, and then uses mode `acl`. Move them into a `secure_messaging` block. | none |

For the build options, see [Build options](build-options.md).

## The card_drivers list

The `card_drivers` setting lists the card drivers that OpenSC tries, in order. Put `acos5_external` first, before the drivers built into OpenSC:

```text
card_drivers = acos5_external, internal;
```

## The card_atr block for the ACOS5-EVO

The ACOS5-EVO needs protocol T=0. The `card_atr` block matches the card by its answer to reset (ATR) and forces T=0. The mask covers the card revisions `41 05 4X` and ignores the last byte of the ATR. To see your card's ATR, run `opensc-tool --atr`. The following block fits every ATR of the form `3B:9E:96:80:01:41:05:4X:00:00:00:00:00:00:00:00:00:90:00:XX`:

```text
card_atr 3B:9E:96:80:01:41:05:43:00:00:00:00:00:00:00:00:00:90:00:1E {
    atrmask = "FF:FF:FF:FF:FF:FF:FF:F0:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:00";
    force_protocol = "t0";
}
```

For the reason, see [Supported cards](supported-cards.md#protocol-t0-on-the-acos5-evo).

## The pkcs15init block

The `pkcs15init acos5_external` block inside `framework pkcs15` registers `libacos5_pkcs15.so`. Its only setting is **module**, the path of the library. `pkcs15-init` also needs the profile file `acos5_external.profile` in the OpenSC profile directory.

The profile has one option for the ACOS5-EVO. `pkcs15-init --profile acos5_external+bound` creates RSA keys that require the user PIN and secure messaging. See [Set up secure messaging](../guides/set-up-secure-messaging.md#create-keys-that-require-secure-messaging).

## The secure_messaging block

The `secure_messaging` block holds the secure messaging settings for the ACOS5-EVO. Its name is free. The `secure_messaging` setting in the `card_driver` block selects it. The block can hold settings for all cards and a `card {SERIAL}` sub-block for each card.

The following table lists the settings. Each setting is valid both at the block level and in a card's sub-block:

| Setting | Required | Description | Default value |
| --- | --- | --- | --- |
| **mode** | No | When the driver uses secure messaging: `none`, `acl`, or `transmit`. See [Secure messaging](../concepts/secure-messaging.md#modes). | `none` |
| **kmc** | No | A 32-byte master key as 64 hexadecimal digits. The driver derives each card's keys from it and the card's serial number. | none |
| **keyset_{AID}_02_enc** | No | Key `82`, the secure messaging key, as 48 hexadecimal digits (AES-192). Needs its partner `_mac`. | none |
| **keyset_{AID}_02_mac** | No | Key `81`, the host authentication key, as 48 hexadecimal digits (AES-192). Needs its partner `_enc`. | none |

`{AID}` is the application identifier of the PKCS#15 application in hexadecimal. For a card that `tools/evo_init.py` initialized, it is `41434F53504B43532D313576312E3030`, which is `ACOSPKCS-15v1.00`. Key values may contain colons or spaces between the digits.

`{SERIAL}` is the card's serial number as 16 hexadecimal digits, as `pkcs11-tool --list-slots` shows it in the `serial num` line.

The driver resolves each setting from the card's sub-block first, then from the block level, then from the default. It looks for keys in the following order:

1. The keyset in the card's sub-block
2. `kmc` in the card's sub-block
3. The keyset at the block level
4. `kmc` at the block level

An invalid key or master key is an error, except in mode `none`. In mode `none`, the driver logs the invalid setting and ignores it.

## The debug log

OpenSC writes the driver's log messages to a file when you set a debug level. The following settings go into the `app default` block:

| Setting | Required | Description | Default value |
| --- | --- | --- | --- |
| **debug** | No | The log level. `3` shows the driver's messages. Some secure messaging messages need `9`. | `0` |
| **debug_file** | No | The path of the log file | `stderr` |

Turn the log off again after use. The log can hold data that goes to and from the card.
