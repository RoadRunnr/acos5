# Secure messaging

Secure messaging (SM) protects the commands between the host and the card. On the ACOS5-EVO, the driver protects a command with a message authentication code (MAC), and optionally encrypts its data. The card checks the MAC and refuses a command that someone changed on the way. Encryption hides the data, for example a PIN, from anyone who reads the reader's USB traffic.

This page describes secure messaging on the ACOS5-EVO. For the older ACOS5-64 V3.00, see the notes on secured PIN entry in [`info/card_initialization`](../../info/card_initialization/README.md).

## How the card and the driver use secure messaging

The card and the host share a static AES-192 key, key `82`. `tools/evo_init.py --sm` writes the key to the card, and you put the same key into `opensc.conf`. The tool also writes a second key, key `81`, for host authentication. Secure messaging does not use key `81`, but the configuration holds it as the partner of key `82`. For each protected command, the driver gets a fresh 16-byte challenge from the card. The challenge sets the start values for the encryption of the command and of the response. The driver computes the MAC with AES-CMAC and encrypts with AES-CBC.

The access conditions on the card set which commands need secure messaging. Each file and each key on the card has access conditions, and an access condition can require a MAC, or a MAC and encryption. The card refuses secure messaging on a command whose access condition does not require it. The host therefore cannot add protection to a file that the card does not protect.

## What secure messaging protects

The protection covers the link between the host and the card:

- An encrypted command hides its data. With a bound card, nobody who reads the reader's USB traffic sees the user PIN.
- A MAC detects a changed command or response.
- A bound card refuses its private keys to any host without the SM keys, even with the correct user PIN.

Secure messaging has the following limits:

- Someone who records a command can send it to the card again, because the MAC does not include the challenge. Encryption does not prevent that either. Use encryption where the data must stay secret.
- Every command uses the same static key. The card has no session keys.
- An attacker who controls the host can read the keys in `opensc.conf`.
- Operations with EC keys go to the card in plain text, unless the card was initialized with `--bind-sign`.

## Modes

The `mode` setting in `opensc.conf` sets when the driver uses secure messaging:

| Mode | Behavior |
| --- | --- |
| `none` | The driver never uses secure messaging. Files and keys that require it do not work. This is the default. |
| `acl` | The driver uses secure messaging where the access condition of the file or key requires it, and sends everything else in plain text. |
| `transmit` | Like `acl`, but the driver refuses to send a PIN, a PUK, or key material in plain text. A PIN command or a key import fails unless the card requires encryption for it. |

`acl` is the mode for normal use. `transmit` is a check that no secret leaves the host in plain text. In mode `transmit`, the SO PIN commands fail, because the SO PIN is outside the bound application.

## Binding a card to its hosts

A card that `tools/evo_init.py --sm --bind` initialized requires secure messaging in these cases:

- PIN commands for the user PIN (verify, change, unblock) need a MAC and encryption.
- Reading the PKCS#15 files needs a MAC.

A host without the SM keys cannot read the PKCS#15 files or verify the user PIN, so it cannot use the card through OpenSC. Writing the PKCS#15 files needs no secure messaging. The SO PIN is outside the bound application and goes to the card in plain text.

The card keeps no record that it is bound. Keys that you create later need the `+bound` profile option to require secure messaging for themselves.

## Binding signing to the hosts

`tools/evo_init.py --bind-sign` binds the card as `--bind` does. It also requires secure messaging with a MAC for every PSO command (signing, decryption) and for key generation in the PKCS#15 application. The requirement covers all keys, EC keys included, without the `+bound` option. The driver reads this requirement from the card and sends these commands under secure messaging.

The card refuses EC key generation under secure messaging, and the binding refuses it in plain text. On a card initialized with `--bind-sign`, import EC keys instead of generating them. RSA keys can be generated.

The binding requires a MAC, but no encryption. The driver sends decryption under secure messaging only with encryption, so on such a card only RSA keys created with `+bound` can decrypt. Their own access condition requires encryption. A `+bound` RSA key also still needs the user PIN together with secure messaging.

## Bound keys

A key created with the profile option `+bound` requires the user PIN and secure messaging together. The card refuses such a key in plain text even after a correct PIN, and it refuses the key under secure messaging without the PIN. The requirement covers signing, decryption, generation, and import. The driver sends each of these commands under secure messaging.

`+bound` works for RSA keys only. `pkcs15-init` refuses `+bound` for EC keys. To bind EC keys, initialize the card with `--bind-sign`. A `+bound` key needs a card with SM keys (`--sm`). The card does not have to be bound with `--bind`.

## Where the keys come from

The driver looks up the keys for each card in `opensc.conf` in the following order:

1. The keys in the card's own sub-block
2. Keys derived from the master key (`kmc`) in the card's sub-block
3. The keys in the `secure_messaging` block
4. Keys derived from the master key in the `secure_messaging` block

The derivation follows NIST SP 800-108 in counter mode with AES-CMAC. It uses the 32-byte master key and the card's 8-byte serial number, so each card gets its own keys from one master key. `tools/evo_init.py --kmc-file` writes the same derived keys to the card.

> [!CAUTION]
> If you lose the SM keys or the master key, you cannot use the bound keys and files of the card. The only recovery is to wipe and initialize the card.

## Related pages

- [Set up secure messaging](../guides/set-up-secure-messaging.md)
- [Configuration reference](../reference/configuration.md#the-secure_messaging-block)
