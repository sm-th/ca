# smime-ca

A small personal certificate authority for S/MIME mail. It creates a root CA
and issues separate signing and encryption certificates, packed as `.p12` for
import into mail clients; a mail bot gets the same pair.

- Keys: EC P-256 (RSA 3072 for `issue encryption --rsa`), stored as encrypted
  PKCS#8 (AES-256-CBC, PBKDF2-HMAC-SHA256, 600000 iterations).
- `.p12`: AES-256-CBC for key and certificates, SHA-256 MAC, 600000 iterations;
  contains the certificate, its key and the CA certificate. `export-p12 --legacy`
  writes a SHA-1/3DES variant for importers that reject AES.
- Kinds: `signing` gets `keyUsage=digitalSignature`, `encryption` gets
  `keyAgreement`, `encryption --rsa` gets `keyEncipherment`. All have
  `extendedKeyUsage=emailProtection` and the address in `subjectAltName`.
  Signing and encryption never share a key.

## Requirements

Nix with flakes enabled. OpenSSL comes from the flake; the system `openssl`
(LibreSSL on macOS) is not used.

## Running

The tool reads the CA passphrase and the CA key, so run a version you have
reviewed, not whatever the branch holds today. Either pin a commit:

```bash
smime-ca() { nix run github:sm-th/ca/<reviewed-commit-sha> -- "$@"; }
```

or use a local clone checked out at a commit you trust (it uses only committed
files):

```bash
smime-ca() { nix run /path/to/clone -- "$@"; }
```

Update the pin deliberately, after reading the diff. The examples below use
this `smime-ca` function.

The tool works in the **current directory** (or `$SMIME_DIR`). Keep the CA in
its own directory outside this repository and run the tool from there:

```bash
mkdir -p ~/maildir && cd ~/maildir

export SMIME_NAME='Your Name'           # CN of the certificates
export SMIME_EMAIL='you@example.com'    # address in subjectAltName

smime-ca init                      # once: create the CA
smime-ca issue signing             # you@example.com/signing.YYYYMMDD.{key.pem,csr.pem,crt.pem,p12}
smime-ca issue encryption --rsa    # you@example.com/encryption-rsa.YYYYMMDD.*
smime-ca list
smime-ca --help                     # full usage
```

## Commands

Certificates live in one directory per address. `CERT` below is a
certificate's path without extension, as printed by `issue`, e.g.
`bot@example.com/signing.20261029`; tab completion works.

| Command | Result |
| --- | --- |
| `init [--name NAME] [--days N]` | `ca.key.pem`, `ca.crt.pem`, `ca.cer` (DER, for import), `ca.cnf`, `ca-db/`. CA subject is `CN=NAME Mail Root CA`, valid 10 years, limited to email by `extendedKeyUsage=emailProtection`. |
| `issue signing\|encryption [--rsa] [--email EMAIL] [--name NAME] [--days N]` | `EMAIL/KIND.YYYYMMDD.{key.pem,csr.pem,crt.pem,p12}` signed by the CA, valid 1 year. `KIND` is `signing`, `encryption` (EC) or `encryption-rsa` (`--rsa`, RSA 3072). `EMAIL` is `--email` or `SMIME_EMAIL`. Refused if the CA expires earlier. |
| `export-p12 CERT [--legacy]` | `CERT.p12`, or `CERT-legacy.p12` with SHA-1/3DES. Never for `ca`. |
| `export-key CERT` | Unencrypted PKCS#8 PEM of the key on stdout, to be piped straight into the service that needs it. Refuses to write to a terminal and never exports `ca`. |
| `cert-mail CERT [--encryption-cert CERT] [--to EMAIL] [--subject TEXT]` | Message signed with `CERT` on stdout: `From` is the address in `CERT`, `To` is `--to` or `SMIME_EMAIL`. The signature carries `CERT`, `ca.crt.pem` and the `--encryption-cert` for the same address. A non-ASCII subject is RFC 2047 encoded. |
| `list` | Serial, subject, expiry, SAN and key usage of every `*.crt.pem` in the directory and in `EMAIL/`, marked `valid` or `EXPIRED`. |

`issue` asks for the CA passphrase (checked immediately), a new key passphrase
and a `.p12` export passphrase (empty = same as the key). All prompts come
before any file is written. Existing files are never overwritten, so the same
kind of certificate for the same address can be issued once a day.

Once the CA has signed, the certificate is recorded in `ca-db/`, so the key and
certificate are kept even if a later step fails. If only the `.p12` failed,
`export-p12 CERT` creates it.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMIME_DIR` | current directory | where the CA and certificates live |
| `SMIME_NAME` | — | CN; required unless `--name` is given |
| `SMIME_EMAIL` | — | your address: `subjectAltName` for `issue` unless `--email` is given, recipient for `cert-mail` unless `--to` is given |
| `KDF_ITER` | `600000` | PBKDF2 iterations for keys and `.p12` |
| `CA_DAYS` | `3650` | CA validity |
| `CERT_DAYS` | `365` | certificate validity |
| `OPENSSL` | `openssl` from the flake | OpenSSL 3 or newer |

## Using the certificates

1. Import `ca.cer` into the mail client (or OS keychain) and trust it for
   email only, e.g. in macOS Keychain set just "Secure Mail (S/MIME)" to
   "Always Trust". Correspondents need it too to validate your signatures.
   Whoever trusts the CA for everything would also accept TLS certificates
   signed with its key. CAs created by `init` carry
   `extendedKeyUsage=emailProtection`, which limits them to email in clients
   that enforce it; CAs made before that (or by hand) do not.
2. Import the `.p12` files. If the importer reports a wrong password for a
   correct one, try `export-p12 CERT --legacy`. If that file is rejected too,
   delete it and lower the iteration count to the classic PKCS#12 default:
   `KDF_ITER=2048 smime-ca export-p12 CERT --legacy`.
   Fewer iterations make guessing the `.p12` passphrase cheaper, so use a
   strong one and delete the file after import.
3. iOS Mail decrypts mail for an RSA encryption certificate, but not mail
   that Thunderbird encrypts for an EC one. To read encrypted mail on an
   iPhone, issue the encryption certificate with `--rsa` and select it as the
   encryption certificate in Thunderbird and on the iPhone; the signing
   certificate can stay EC.

Keep old encryption keys (`*.encryption*.key.pem` / `.p12`) after the certificate expires:
without them mail encrypted to the old certificate can no longer be read.

## No revocation

The CA publishes no CRL, so a certificate cannot be revoked: it stays valid
for everyone who trusts the CA until it expires. If a certificate's key is
compromised, either accept that until expiry or create a new CA, distribute its
`ca.cer` and reissue all certificates. If the CA key is compromised, a new CA is
the only option.

## Bot certificates

A bot that signs its mail and receives encrypted mail gets two certificates,
like a person: one key signs, the other decrypts. With a single RSA key, a bot
that leaks whether decryption failed would also let an attacker sign as the bot
([ROBOT](https://robotattack.org/)). Use `--rsa` for the encryption key if
iPhones must encrypt mail to the bot.

```bash
smime-ca issue signing --email bot@example.com --name 'Mail Bot'
smime-ca issue encryption --rsa --email bot@example.com --name 'Mail Bot'

# the bot cannot type a passphrase: give it the unencrypted keys, never via a file
smime-ca export-key bot@example.com/signing.YYYYMMDD | <bot secret store>
smime-ca export-key bot@example.com/encryption-rsa.YYYYMMDD | <bot secret store>

# a signed message that carries both bot certificates and ca.crt.pem
smime-ca cert-mail bot@example.com/signing.YYYYMMDD \
  --encryption-cert bot@example.com/encryption-rsa.YYYYMMDD --to you@example.com > bot.eml
```

Pass `--email`: without it the certificate gets `SMIME_EMAIL`, your own address.
Opening `bot.eml` in a mail client (e.g. after copying it into a mailbox
folder) lets the client install the bot's certificates, so it can encrypt mail
to the bot.

## Notes

- Passphrases are passed to OpenSSL through file descriptors, not command line
  arguments or environment variables.
- New files are created with `umask 077` in a temporary directory and moved
  into place when complete (see the `issue` exception above).
- `.gitignore` excludes keys, certificates and CA state in case the tool is run
  inside the repository.
