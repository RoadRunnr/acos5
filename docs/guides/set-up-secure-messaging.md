# Set up secure messaging

This guide sets up secure messaging (SM) for an ACOS5-EVO: the keys on the card, the same keys in `opensc.conf`, and keys on the card that require secure messaging. For what secure messaging protects, see [Secure messaging](../concepts/secure-messaging.md).

## Prerequisites

Before you begin, make sure you have the following:

- The driver installed and registered. See [Installation](../installation.md).
- Python 3 with the `pyscard` and `cryptography` modules
- `sudo` rights to change `/etc/opensc/opensc.conf`

## Put the keys on the card

The SM keys go to the card at initialization. A card initialized without `--sm` has no SM keys.

> [!CAUTION]
> Initialization deletes everything on the card: keys, certificates, and PINs.

Run the following command to initialize the card with random SM keys and bind it:

```bash
python3 tools/evo_init.py --user-pin {USER_PIN} --user-puk {USER_PUK} --so-pin {SO_PIN} --so-puk {SO_PUK} --sm --bind
```

The tool writes the keys to `~/.config/acos5evo/{SERIAL}.conf` with mode 600. The file holds a `card` sub-block for `opensc.conf`. Leave out `--bind` if the card should work without SM keys for PIN commands. For the setup options, see [Initialize a card](initialize-a-card.md#choose-the-setup).

## Add the keys to opensc.conf

The driver reads the keys from a `secure_messaging` block in `opensc.conf`. Choose one of the following procedures.

### Install the card's sub-block with the script

`tools/evo_conf_install.sh` merges the card's sub-block into `/etc/opensc/opensc.conf`. It adds the `secure_messaging` block and the setting that names it if they are missing. It replaces an existing sub-block for the same card. It backs up the file to `opensc.conf.bak-{DATE}` first, keeps the file's owner and mode, and prints no key values.

Run the script with the card's serial number. `tools/evo_init.py` prints the path of the sub-block file, which contains the serial number:

```bash
bash tools/evo_conf_install.sh {SERIAL}
```

### Write the block by hand

The following snippet shows the configuration for one card with its own keys. Put it into the `app default` block:

```text
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
```

Copy the `card` sub-block from `~/.config/acos5evo/{SERIAL}.conf`. The block-level `mode = none` keeps other cards in plain text.

For cards with keys derived from a master key, write the master key once in the block, and set the mode there:

```text
secure_messaging acos5_evo {
    mode = acl;
    kmc = "{MASTER_KEY_64_HEX_DIGITS}";
}
```

> [!IMPORTANT]
> `opensc.conf` now holds secret keys. Make the file readable only by root and the users of the card, for example with mode 0640 and the users' group.

For every setting, see [Configuration reference](../reference/configuration.md#the-secure_messaging-block).

## Create keys that require secure messaging

Keys that you create on a card with SM keys do not require secure messaging by themselves, even on a bound card. Add the profile option `+bound` to create an RSA key that the card uses only under secure messaging and with the user PIN. The card needs SM keys (`--sm`), but it does not have to be bound:

```bash
pkcs15-init --profile acos5_external+bound --generate-key rsa/2048 --auth-id 01 --id {ID} --label {LABEL} --key-usage sign,decrypt
```

The option also works with `--store-private-key`. `pkcs15-init` refuses it for EC keys.

## Verification

Run the following command to check that the driver reads the bound card:

```bash
pkcs15-tool --list-pins
```

On a bound card, the command lists the PINs only when the driver has the right keys in mode `acl` or `transmit`. Otherwise the command fails, because the card refuses to show the PKCS#15 files in plain text.

Run the following command to check that the user PIN works under secure messaging:

```bash
pkcs15-tool --verify-pin --auth-id 01
```

To see which mode and key source the driver uses, turn on the debug log with `debug = 3;`. Then look for log lines that contain `secure_messaging: card`. For the log settings, see [Troubleshooting](../troubleshooting.md#turn-on-the-debug-log).

> [!NOTE]
> If the verification fails, see [Troubleshooting](../troubleshooting.md#secure-messaging-errors).
