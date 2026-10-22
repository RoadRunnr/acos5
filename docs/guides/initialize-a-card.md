# Initialize a card

Card initialization wipes the card and creates the PKCS#15 file system that OpenSC and the driver use. It creates the PINs, the security environment, and the empty PKCS#15 directory files. After that, you use the standard OpenSC tools for everything else: `pkcs15-init`, `pkcs15-tool`, `pkcs11-tool`, and any PKCS#11 application.

The driver does not implement the initialization functions of `pkcs15-init`, so `pkcs15-init --create-pkcs15` does not work. Use the tool for your card instead:

| Card | Tool |
| --- | --- |
| ACOS5-64 V2.00 (CryptoMate64), ACOS5-64 V3.00 (CryptoMate Nano) | The `scriptor` script in [`info/card_initialization`](../../info/card_initialization/README.md) |
| ACOS5-EVO (Smart Card EVO, CryptoMate EVO) | `tools/evo_init.py`, described on this page |

A card that ACS software initialized does not work with this driver. Its file system does not follow the PKCS#15 layout that OpenSC expects. Initialize the card again.

## Prerequisites

Before you initialize an ACOS5-EVO, make sure you have the following:

- The driver installed and registered. See [Installation](../installation.md).
- Python 3 with the `pyscard` and `cryptography` modules
- One card reader with the card, or the `EVO_READER` environment variable set to a part of the reader's name

## Choose the setup

`evo_init.py` creates one of three setups. Choose the setup before you start, because you can change it later only by wiping the card again.

| Setup | Command options | Use for |
| --- | --- | --- |
| Plain | none | A card that needs no secure messaging. The PINs go to the card in plain text. |
| Secure messaging keys | `--sm` | A card that has secure messaging keys. Single keys and files can require secure messaging. |
| Bound | `--sm --bind` | A card that works only with hosts that have its secure messaging keys. The user PIN goes to the card only encrypted. |
| Bound with signing | `--sm --bind-sign` | Like bound, and every signature and key generation on the card needs secure messaging. The card cannot generate EC keys in this setup, so import them. Only RSA keys created with `+bound` can decrypt. |

For what secure messaging protects and what it does not protect, see [Secure messaging](../concepts/secure-messaging.md).

## Initialize an ACOS5-EVO

The tool sends every command through a guard that refuses commands that could lock the card. It refuses cards that are not an ACOS5-EVO.

> [!CAUTION]
> `evo_init.py` deletes everything on the card: keys, certificates, and PINs. You cannot recover deleted keys. If the tool fails partway, it wipes the card again.

1. Run the tool with the PINs and PIN Unblocking Keys (PUKs) you want to set. Add `--sm` or `--sm --bind` for the setup you chose:

   ```bash
   python3 tools/evo_init.py --user-pin {USER_PIN} --user-puk {USER_PUK} --so-pin {SO_PIN} --so-puk {SO_PUK} --sm --bind
   ```

2. Type `yes` when the tool asks to wipe the card.

The tool lists each step and ends with the free space on the card:

```text
...
{N} ok  activate MF
done: {N} steps; free space now {BYTES} bytes
```

The number of steps depends on the setup.

PINs and PUKs have four to eight characters. Without the PIN options, the user PIN is `12345678` and the Security Officer (SO) PIN is `87654321`. Without a PUK option, a PUK gets the value of its PIN.

> [!IMPORTANT]
> Set the PUKs at initialization. You can change the PINs later with `pkcs15-tool`, but `pkcs15-tool` and `pkcs11-tool` have no option to change a PUK. To change a PUK later, you have to wipe and initialize the card again.

### Secure messaging keys

With `--sm`, the tool generates two random AES-192 keys, writes them to the card, and stores them in `~/.config/acos5evo/{SERIAL}.conf` with mode 600. If that file already exists, the tool reuses its keys.

> [!CAUTION]
> Keep a copy of the key file. Without the keys, you cannot use keys and files that require secure messaging. The only recovery is to wipe the card.

To derive the keys from a master key instead, put 64 hexadecimal digits in a file that only you can read, and pass the file:

```bash
python3 tools/evo_init.py --kmc-file {PATH_TO_MASTER_KEY_FILE} --bind
```

`--kmc-file` implies `--sm`. The tool derives each card's keys from the master key and the card's serial number, so one master key serves many cards. The card's configuration file then holds no keys. Put the master key into `opensc.conf` as described in [Set up secure messaging](set-up-secure-messaging.md).

### Other options

The tool has the following other options:

- `--wipe-only` wipes the card and creates nothing.
- `--yes` wipes without asking.

## Verification

Run the following command to list the PINs on the new card:

```bash
pkcs15-tool --list-pins
```

A card that `evo_init.py` initialized has the user PIN with ID `01` and the SO PIN with ID `02`:

```text
PIN [User]
	Object Flags   : [0x03], private, modifiable
	ID             : 01
	...
	Tries left     : 8

PIN [SO]
	Object Flags   : [0x03], private, modifiable
	ID             : 02
	...
	Tries left     : 8
```

On a bound card, this command works only after you set up secure messaging in `opensc.conf`. See [Set up secure messaging](set-up-secure-messaging.md).

> [!IMPORTANT]
> If you kept the default PINs, change them before you store keys on the card. See [Manage PINs](manage-pins.md).

## Next steps

- [Manage PINs](manage-pins.md)
- [Manage keys and certificates](manage-keys-and-certificates.md)
- [Set up secure messaging](set-up-secure-messaging.md)
