# Use the card with applications

Applications use the card through the OpenSC PKCS#11 module. This guide shows OpenSSH, OpenSSL, and NSS, which Firefox and Thunderbird use. On Debian and Ubuntu, the module is `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`. The examples write it as `{PKCS11_MODULE}`.

All examples need a key pair on the card. See [Manage keys and certificates](manage-keys-and-certificates.md).

## OpenSSH

OpenSSH can use RSA and EC keys from the card for authentication and for signatures.

### Log in to a server with a key from the card

1. Print the public keys on the card in OpenSSH format:

   ```bash
   ssh-keygen -D {PKCS11_MODULE}
   ```

   Alternatively, print one key by its ID:

   ```bash
   pkcs15-tool --read-ssh-key {ID}
   ```

2. Add the public key to `~/.ssh/authorized_keys` on the server, or to your account on a Git hosting service.

3. Connect with the key from the card:

   ```bash
   ssh -I {PKCS11_MODULE} {USER}@{HOST}
   ```

To use the card for every connection, add the following line to `~/.ssh/config`:

```text
PKCS11Provider {PKCS11_MODULE}
```

For GitHub, the test command is `ssh -T git@github.com`. GitHub answers with a greeting that contains your user name.

### Load the keys into ssh-agent

Run the following command to load the keys into a running `ssh-agent`:

```bash
ssh-add -s {PKCS11_MODULE}
```

`ssh-add` asks for the user PIN. The agent then signs with the card for every program that uses the agent. To remove the keys from the agent, run `ssh-add -e {PKCS11_MODULE}`.

### Sign a file with ssh-keygen

With the keys in the agent, you can sign a file:

```bash
ssh-add -L > card-keys.pub
ssh-keygen -Y sign -f {PUBLIC_KEY_FILE} -n file {FILE}
```

`{PUBLIC_KEY_FILE}` is a file with one line of `card-keys.pub`. The command writes the signature to `{FILE}.sig`.

## OpenSSL with pkcs11-provider

OpenSSL 3 uses the card through [pkcs11-provider](https://github.com/latchset/pkcs11-provider). On Debian and Ubuntu, install the `pkcs11-provider` package.

1. Tell the provider which PKCS#11 module to load:

   ```bash
   export PKCS11_PROVIDER_MODULE={PKCS11_MODULE}
   ```

2. Sign a file with the private key with ID `{ID}`:

   ```bash
   openssl pkeyutl -provider pkcs11 -provider default -sign -rawin -digest sha256 -inkey "pkcs11:id=%{ID};type=private" -in {FILE} -out {FILE}.sig
   ```

3. Create a certificate signing request (CSR) with the same key:

   ```bash
   openssl req -provider pkcs11 -provider default -new -key "pkcs11:id=%{ID};type=private" -subj /CN={NAME} -out request.pem
   ```

OpenSSL asks for the user PIN. The PKCS#11 URI selects the key by its ID. For example, `pkcs11:id=%01;type=private` selects the key with ID `01`.

## NSS, Firefox, and Thunderbird

NSS loads PKCS#11 modules into its database. Firefox and Thunderbird have their own NSS database in the profile directory.

1. Add the module to an NSS database:

   ```bash
   modutil -dbdir sql:{NSS_DB_DIR} -add opensc -libfile {PKCS11_MODULE}
   ```

2. List the certificates, including those on the card:

   ```bash
   certutil -d sql:{NSS_DB_DIR} -L -h all
   ```

`modutil` and `certutil` are in the `libnss3-tools` package. In Firefox and Thunderbird, you can add the module in the settings under **Security Devices** instead.

## Next steps

- [Manage keys and certificates](manage-keys-and-certificates.md)
- [Troubleshooting](../troubleshooting.md)
