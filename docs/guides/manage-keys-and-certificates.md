# Manage keys and certificates

This guide shows how to put keys and certificates on an initialized card and how to test them. It uses the OpenSC command-line tools:

- `pkcs15-init` writes to the card: it generates and imports keys, stores certificates, and deletes objects.
- `pkcs15-tool` reads PKCS#15 objects, for example public keys and certificates.
- `pkcs11-tool` uses the keys through the OpenSC PKCS#11 module, as applications do.

The examples use the following placeholders:

| Placeholder | Meaning |
| --- | --- |
| `{ID}` | A key ID in hexadecimal, for example `01`. A key pair and its certificate share one ID. |
| `{LABEL}` | A name for the key, for example `ssh-key` |
| `{PKCS11_MODULE}` | The OpenSC PKCS#11 module, on Debian and Ubuntu `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |

The commands omit `--pin` and `--so-pin`. The tools ask for the PINs.

## Supported key types

The following table lists the key types that the driver supports on the card:

| Key type | Sizes or curves | Cards |
| --- | --- | --- |
| RSA | 512 to 4096 bits in steps of 256 | All supported cards |
| EC | P-224, P-256, P-384, P-521 | ACOS5-EVO only |

On the ACOS5-EVO, RSA-2048 and RSA-4096 keys and all four curves are tested for generation and use. EC keys can only sign. The driver supports no key agreement (ECDH).

## Generate a key pair

The card generates the key pair. The private key never leaves the card.

1. Run the following command to generate an RSA key that can sign and decrypt:

   ```bash
   pkcs15-init --generate-key rsa/2048 --auth-id 01 --id {ID} --label {LABEL} --key-usage sign,decrypt
   ```

2. Enter the user PIN.

For an EC key, use the curve name and the `sign` usage:

```bash
pkcs15-init --generate-key ec/prime256v1 --auth-id 01 --id {ID} --label {LABEL} --key-usage sign
```

The curve names are `secp224r1`, `prime256v1`, `secp384r1`, and `secp521r1`. `--auth-id 01` makes the user PIN protect the private key.

The driver puts each key pair into two files in the range `5000` to `5FFF` of the application directory. Generation of an RSA-4096 key can take more than ten minutes. That figure was measured on an ACOS5-EVO.

## Import a private key

You can also write an existing private key to the card. The key then exists outside the card too, so protect or delete the key file afterwards.

1. Run the following command with a PEM file that holds an RSA or EC private key:

   ```bash
   pkcs15-init --store-private-key {KEY_FILE} --auth-id 01 --id {ID} --label {LABEL} --key-usage sign
   ```

2. Enter the user PIN.

EC private keys are imported for signing only. Key import is tested on the ACOS5-EVO only.

## Read a public key

Run the following command to save the public key of a key pair as a PEM file:

```bash
pkcs15-tool --read-public-key {ID} -o {PUBLIC_KEY_FILE}
```

## Store a certificate

Store the certificate with the ID of its key pair.

> [!IMPORTANT]
> Always pass `--label`. OpenSC gives the private key with the same ID the certificate's label.

1. Run the following command:

   ```bash
   pkcs15-init --store-certificate {CERTIFICATE_FILE} --format pem --auth-id 01 --id {ID} --label {LABEL}
   ```

2. Enter the user PIN.

The driver stores the certificate inside the certificate directory file (EF.CDF). On a card that `tools/evo_init.py` initialized, that file holds 6 KB, which is enough for a few certificates.

To issue a test certificate for a key on the card, sign its public key with a local test CA (certificate authority):

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -subj /CN=test-ca -days 30 -out ca.pem
openssl x509 -new -subj /CN={LABEL} -force_pubkey {PUBLIC_KEY_FILE} -CA ca.pem -CAkey ca.key -days 30 -out {CERTIFICATE_FILE}
```

To read a certificate back, run the following command:

```bash
pkcs15-tool --read-certificate {ID}
```

## List the objects on the card

Run the following command to list the keys:

```bash
pkcs15-tool --list-keys
```

To see the objects as PKCS#11 applications see them, run the following command:

```bash
pkcs11-tool --module {PKCS11_MODULE} --list-objects
```

## Test a key

These commands sign and decrypt through PKCS#11 and check the results with OpenSSL.

1. Create a test message:

   ```bash
   echo "test message" > msg.txt
   ```

2. Sign the message with an RSA key:

   ```bash
   pkcs11-tool --module {PKCS11_MODULE} --login --sign --mechanism SHA256-RSA-PKCS --id {ID} -i msg.txt -o msg.sig
   ```

3. Verify the signature with the public key:

   ```bash
   openssl dgst -sha256 -verify {PUBLIC_KEY_FILE} -signature msg.sig msg.txt
   ```

OpenSSL prints `Verified OK`.

For an EC key, use the mechanism `ECDSA-SHA256`. The card returns the signature as the raw values r and s.

To test decryption with an RSA key, encrypt a short file with the public key and decrypt it on the card:

```bash
openssl pkeyutl -encrypt -pubin -inkey {PUBLIC_KEY_FILE} -pkeyopt rsa_padding_mode:pkcs1 -in msg.txt -out msg.enc
pkcs11-tool --module {PKCS11_MODULE} --login --decrypt --mechanism RSA-PKCS --id {ID} -i msg.enc -o msg.dec
cmp msg.txt msg.dec
```

## Delete a key and its certificate

The driver deletes the key files, which frees their space on the card. Enter the PINs that `pkcs15-init` asks for.

> [!CAUTION]
> A deleted private key is gone. Data encrypted for that key cannot be decrypted any more. Check the ID with `pkcs15-tool --list-keys` before you delete.

Run the following command to delete the private key, the public key, and the certificate with one ID:

```bash
pkcs15-init --delete-objects privkey,pubkey,cert --id {ID}
```

## Check the card content

`pkcs15-init --sanity-check` reads the card's file system and PKCS#15 content and reports what does not match. Run it after changes made with other tools, or when the driver reports errors:

```bash
pkcs15-init --sanity-check
```

The command reports each problem in a line that starts with `[X] ERROR`. For the rules that the card content must follow, see [Card content rules](../reference/card-content-rules.md).

## Keys that need secure messaging

On an ACOS5-EVO initialized with `--sm`, you can create RSA keys that the card uses only under secure messaging. Add the profile option `+bound` to the generate or import command:

```bash
pkcs15-init --profile acos5_external+bound --generate-key rsa/2048 --auth-id 01 --id {ID} --label {LABEL} --key-usage sign,decrypt
```

For the setup and the limits, see [Set up secure messaging](set-up-secure-messaging.md).
