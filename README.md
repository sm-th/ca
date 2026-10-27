# smime-ca

A small personal certificate authority for S/MIME mail. It creates a root CA
and issues separate encryption and signing certificates, packed as `.p12` for
import into mail clients.

- Keys: EC P-256, stored as encrypted PKCS#8 (AES-256-CBC, PBKDF2-HMAC-SHA256,
  600000 iterations).
- `.p12`: AES-256-CBC for key and certificates, SHA-256 MAC, 600000 iterations;
  contains the certificate, its key and the CA certificate.
- Encryption certificates get `keyUsage=keyAgreement`, signing certificates get
  `keyUsage=digitalSignature`; both have `extendedKeyUsage=emailProtection` and
  the address in `subjectAltName`.

## Requirements

Nix with flakes enabled. OpenSSL 3 comes from the flake; the system `openssl`
(LibreSSL on macOS) is not used.

## Running

The tool works in the **current directory** (or `$SMIME_DIR`). Keep the CA in
its own directory outside this repository and run the flake from there:

```bash
mkdir -p ~/maildir && cd ~/maildir

export SMIME_NAME='Your Name'           # CN of the certificates
export SMIME_EMAIL='you@example.com'    # address in subjectAltName

nix run /path/to/this/repo -- init                       # once: create the CA
nix run /path/to/this/repo -- issue encryption           # encryption.{key.pem,csr.pem,crt.pem,p12}
nix run /path/to/this/repo -- issue signing thunderbird  # signing-thunderbird.*
nix run /path/to/this/repo -- list
```

Instead of a local path, any flake reference works, e.g.
`nix run github:OWNER/REPO -- list`. Arguments after `--` go to the tool;
`nix run /path/to/this/repo -- --help` prints the full usage.

A local path to a git checkout uses only committed files.

## Commands

| Command | Result |
| --- | --- |
| `init [--name NAME] [--days N]` | `ca.key.pem`, `ca.crt.pem`, `ca.cer` (DER, for import), `ca.cnf`, `ca-db/`. CA subject is `CN=NAME Mail Root CA`, valid 10 years. |
| `issue encryption\|signing [LABEL] [--name NAME] [--email EMAIL] [--days N]` | `PROFILE[-LABEL].{key.pem,csr.pem,crt.pem,p12}` signed by the CA, valid 1 year. |
| `list` | Serial, subject, expiry, SAN and key usage of every `*.crt.pem`, marked `valid` or `EXPIRED`. |

`issue` asks for the CA passphrase (checked immediately), a new key passphrase
and a `.p12` export passphrase (empty = same as the key). All prompts come
before any file is written. Existing files are never overwritten: use a LABEL
for another certificate of the same profile, e.g. `issue encryption 2027`.

## Environment

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMIME_DIR` | current directory | where the CA and certificates live |
| `SMIME_NAME` | — | CN; required unless `--name` is given |
| `SMIME_EMAIL` | — | `subjectAltName` address; required for `issue` unless `--email` is given |
| `KDF_ITER` | `600000` | PBKDF2 iterations for keys and `.p12` |
| `CA_DAYS` | `3650` | CA validity |
| `CERT_DAYS` | `365` | certificate validity |
| `OPENSSL` | `openssl` from the flake | OpenSSL 3 binary |

## Using the certificates

1. Import `ca.cer` into the mail client (or OS keychain) and trust it for
   email. Correspondents need it too to validate your signatures.
2. Import the `.p12` files.

Keep old `encryption*.key.pem` / `.p12` after the certificate expires:
without them mail encrypted to the old certificate can no longer be read.

## Notes

- Passphrases are passed to OpenSSL through file descriptors, not command line
  arguments or environment variables.
- Files are created with `umask 077` in a temporary directory and moved into
  place only after every step succeeded.
- `.gitignore` excludes keys, certificates and CA state in case the tool is run
  inside the repository.
