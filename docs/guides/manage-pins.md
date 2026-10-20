# Manage PINs

The card has two PINs. The user PIN protects the private keys. The Security Officer (SO) PIN protects the card's file system, for example when you delete keys. Each PIN has a PIN Unblocking Key (PUK) that resets the PIN after too many wrong tries.

The OpenSC tools select a PIN by its authentication ID (auth ID) in PKCS#15. The card itself numbers the PINs with a PIN reference. On a card that `tools/evo_init.py` initialized, the PINs are the following:

| PIN | Auth ID | PIN reference on the card | Default value | Tries |
| --- | --- | --- | --- | --- |
| User PIN | `01` | `81` | `12345678` | 8 |
| SO PIN | `02` | `01` | `87654321` | 8 |

Cards initialized with the scripts for the ACOS5-64 V2.00 and V3.00 can use other IDs. Run `pkcs15-tool --list-pins` to see the IDs on your card.

The commands on this page omit `--pin`, `--new-pin`, and `--puk`. The tools then ask for the values, which keeps them out of your shell history.

## Show the PINs and their tries

Run the following command to list the PINs and the tries left:

```bash
pkcs15-tool --list-pins
```

After a correct PIN, the card reports no counter until the next card reset. `pcscd` keeps a verified PIN across programs until the card resets.

## Change a PIN

1. Run the following command to change the user PIN:

   ```bash
   pkcs15-tool --change-pin --auth-id 01
   ```

2. Enter the current PIN, then the new PIN twice.

To change the SO PIN, use `--auth-id 02`. A PIN has four to eight characters.

## Unblock the user PIN

After eight wrong tries, the card blocks the user PIN. The PUK sets a new PIN and resets the counter.

> [!CAUTION]
> The PUK has its own counter with eight tries. If the PUK is blocked too, you cannot use the keys that the user PIN protects. The only recovery is to wipe and initialize the card.

1. Run the following command:

   ```bash
   pkcs15-tool --unblock-pin --auth-id 01
   ```

2. Enter the PUK, then the new PIN twice.

## Verification

Run the following command to check a PIN without using a key:

```bash
pkcs15-tool --verify-pin --auth-id 01
```

The command returns exit code 0 when the PIN is correct.

## PINs and secure messaging

On a card initialized with `--sm --bind`, the driver sends the user PIN to the card only encrypted. Hosts without the card's secure messaging keys cannot verify the user PIN. The SO PIN is outside the bound application, so it goes to the card in plain text. In mode `transmit`, the driver refuses commands that would send a PIN in plain text, so SO PIN commands fail in that mode. For details, see [Secure messaging](../concepts/secure-messaging.md).
