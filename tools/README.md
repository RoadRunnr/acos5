# ACOS5-EVO tools

These Python tools initialize an ACOS5-EVO card for OpenSC and the acos5 driver, and manage its secure messaging configuration. For a step-by-step guide, see [Initialize a card](../docs/guides/initialize-a-card.md).

The tools need Python 3 with the `pyscard` and `cryptography` modules. On Debian and Ubuntu, install `python3-pyscard` and `python3-cryptography`.

The following table lists the files:

| File | Purpose |
| --- | --- |
| `evo_init.py` | Wipes the card and creates the PKCS#15 file system, optionally with secure messaging keys |
| `evo_conf_install.sh` | Merges a card's secure messaging settings into `/etc/opensc/opensc.conf` |
| `safecard.py` | Sends commands to the card and refuses commands that could lock it |
| `evo_layout.py`, `evo_records.py` | Build the commands for the file system. They do not access the card. |
| `evo_card_conf.py` | Reads and writes the per-card configuration file |
| `evo_kdf.py` | Derives a card's keys from a master key |
| `tests/test_conf_install.sh` | Tests `evo_conf_install.sh` on a temporary file, without `sudo` and without a card |

## evo_init.py

> [!CAUTION]
> `evo_init.py` deletes everything on the card: keys, certificates, and PINs.

`evo_init.py` accepts the following options:

| Option | Description | Default value |
| --- | --- | --- |
| `--user-pin`, `--user-puk` | User PIN and its PUK, four to eight characters | `12345678`, PUK equal to the PIN |
| `--so-pin`, `--so-puk` | Security Officer (SO) PIN and its PUK, four to eight characters | `87654321`, PUK equal to the PIN |
| `--sm` | Writes two AES-192 keys for secure messaging to the card. The keys come from `~/.config/acos5evo/{SERIAL}.conf` if that file exists. Otherwise the tool generates random keys and writes them to that file. | off |
| `--kmc-file {PATH}` | Derives the keys from a 32-byte master key, stored as 64 hexadecimal digits in `{PATH}`. The file must not be accessible by group or others. Implies `--sm`. | none |
| `--bind` | Requires secure messaging for the user PIN commands and for reading the PKCS#15 files. Needs `--sm`. | off |
| `--bind-sign` | Also requires secure messaging (MAC) for PSO commands and key generation in the PKCS#15 application. Implies `--bind`. The card then cannot generate EC keys, so import them. Only RSA keys created with `+bound` can decrypt. | off |
| `--wipe-only` | Wipes the card and creates nothing. | off |
| `--yes` | Wipes without asking. | off |

The tool reads the environment variable `EVO_READER`. Set it to a part of the reader's name when several readers are attached.

The tool refuses cards that are not an ACOS5-EVO. It never sends commands that change the card's life cycle or its header block. The card stays in its manufacturer stage, so you can always wipe it again. If a step fails, the tool wipes the card again and exits with code 1.

The tool logs every command to `~/.config/acos5evo/evo-apdu.log`. The log shows PINs, PUKs, and keys as `<data redacted>`.

## evo_conf_install.sh

Run the script with the card's serial number after `evo_init.py --sm`:

```bash
bash tools/evo_conf_install.sh {SERIAL}
```

The script reads `~/.config/acos5evo/{SERIAL}.conf` and changes `/etc/opensc/opensc.conf` with `sudo`. It backs up the file to `opensc.conf.bak-{DATE}` first, keeps the file's owner and mode, and prints no key values. The environment variables `EVO_CONF`, `EVO_CARD_CONF`, and `EVO_NO_SUDO=1` select other files and turn off `sudo`, for tests.
