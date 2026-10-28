# smime-ca

A small personal certificate authority for S/MIME mail. It creates a root CA,
issues separate encryption and signing certificates packed as `.p12` for
import into mail clients, and a combined certificate for a mail bot.

- Keys: EC P-256, stored as encrypted PKCS#8 (AES-256-CBC, PBKDF2-HMAC-SHA256,
  600000 iterations).
- `.p12`: AES-256-CBC for key and certificates, SHA-256 MAC, 600000 iterations;
  contains the certificate, its key and the CA certificate. `export-p12 --legacy`
  writes a SHA-1/3DES variant for importers that reject AES.
- Profiles: `encryption` gets `keyUsage=keyAgreement`, `signing` gets
  `digitalSignature`, `bot` gets both. All have
  `extendedKeyUsage=emailProtection` and the address in `subjectAltName`.

## Requirements

Nix with flakes enabled. OpenSSL comes from the flake; the system `openssl`
(LibreSSL on macOS) is not used.

## Running

The tool works in the **current directory** (or `$SMIME_DIR`). Keep the CA in
its own directory outside this repository and run the flake from there:

```bash
mkdir -p ~/maildir && cd ~/maildir

export SMIME_NAME='Your Name'           # CN of the certificates
export SMIME_EMAIL='you@example.com'    # address in subjectAltName

nix run github:sm-th/ca -- init                       # once: create the CA
nix run github:sm-th/ca -- issue encryption           # encryption.{key.pem,csr.pem,crt.pem,p12}
nix run github:sm-th/ca -- issue signing thunderbird  # signing-thunderbird.*
nix run github:sm-th/ca -- list
```

Arguments after `--` go to the tool; `nix run github:sm-th/ca -- --help`
prints the full usage. Add `--refresh` to pick up the latest commit.

A local clone works too: `nix run /path/to/clone -- list`. It uses only
committed files.

## Commands

`CERT` below is a certificate's file name without extension, e.g. `bot` or
`signing-thunderbird`.

| Command | Result |
| --- | --- |
| `init [--name NAME] [--days N]` | `ca.key.pem`, `ca.crt.pem`, `ca.cer` (DER, for import), `ca.cnf`, `ca-db/`. CA subject is `CN=NAME Mail Root CA`, valid 10 years. |
| `issue encryption\|signing [LABEL] [--name NAME] [--email EMAIL] [--days N]` | `PROFILE[-LABEL].{key.pem,csr.pem,crt.pem,p12}` signed by the CA, valid 1 year. |
| `issue bot [LABEL] --email BOT_EMAIL [--name NAME] [--days N]` | `bot[-LABEL].{key.pem,csr.pem,crt.pem}`, no `.p12`. `--email` is required so the bot never gets your address. |
| `export-p12 CERT [--legacy]` | `CERT.p12`, or `CERT-legacy.p12` with SHA-1/3DES. |
| `export-key CERT` | Unencrypted PKCS#8 PEM of the key on stdout, to be piped straight into the service that needs it. Refuses to write to a terminal. |
| `cert-mail CERT [--to EMAIL] [--subject TEXT]` | Message signed with `CERT` on stdout: `From` is the address in `CERT`, `To` is `--to` or `SMIME_EMAIL`. |
| `list` | Serial, subject, expiry, SAN and key usage of every `*.crt.pem`, marked `valid` or `EXPIRED`. |

`issue` asks for the CA passphrase (checked immediately), a new key passphrase
and a `.p12` export passphrase (empty = same as the key). All prompts come
before any file is written. Existing files are never overwritten: use a LABEL
for another certificate of the same profile, e.g. `issue encryption 2027`.

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
   email. Correspondents need it too to validate your signatures.
2. Import the `.p12` files. If the importer reports a wrong password for a
   correct one, try `export-p12 CERT --legacy`. If that file is rejected too,
   delete it and lower the iteration count to the classic PKCS#12 default:
   `KDF_ITER=2048 nix run github:sm-th/ca -- export-p12 CERT --legacy`.
   Fewer iterations make guessing the `.p12` passphrase cheaper, so use a
   strong one and delete the file after import.

Keep old `encryption*.key.pem` / `.p12` after the certificate expires:
without them mail encrypted to the old certificate can no longer be read.

## No revocation

The CA publishes no CRL, so a certificate cannot be revoked: it stays valid
for everyone who trusts the CA until it expires. If a certificate's key is
compromised, either accept that until expiry or create a new CA, distribute its
`ca.cer` and reissue all certificates. If the CA key is compromised, a new CA is
the only option.

## Bot certificate

A bot that receives encrypted mail and hands out its certificate needs one key
for both decryption and signing:

```bash
nix run github:sm-th/ca -- issue bot --email bot@example.com --name 'Mail Bot'

# the bot cannot type a passphrase: give it the unencrypted key, never via a file
nix run github:sm-th/ca -- export-key bot | wrangler secret put BOT_KEY

# a signed message that carries bot.crt.pem and ca.crt.pem
nix run github:sm-th/ca -- cert-mail bot --to you@example.com > bot.eml
```

Opening `bot.eml` in a mail client (e.g. after copying it into a mailbox
folder) lets the client install the bot's certificate, so it can encrypt mail
to the bot.

## Notes

- Passphrases are passed to OpenSSL through file descriptors, not command line
  arguments or environment variables.
- New files are created with `umask 077` in a temporary directory and moved
  into place when complete (see the `issue` exception above).
- `.gitignore` excludes keys, certificates and CA state in case the tool is run
  inside the repository.
