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
(LibreSSL on macOS) is not used. Without Nix (e.g. on an offline machine),
`bash smime-ca.sh …` works with bash and OpenSSL 3 or newer.

## Running

The tool reads the CA passphrase and the CA key, so run a version you have
reviewed, not whatever the branch holds today. Pin a full commit SHA:

```bash
CA=github:sm-th/ca/<reviewed-commit-sha>
nix run $CA -- --help
```

or define a shell function with the same pin, or run a local clone checked out
at a commit you trust (it uses only committed files):

```bash
smime-ca() { nix run github:sm-th/ca/<reviewed-commit-sha> -- "$@"; }
smime-ca() { nix run /path/to/clone -- "$@"; }
```

Update the pin deliberately, after reading the diff. The examples below use the
`smime-ca` function; `nix run $CA --` works the same way.

The tool works in the **current directory** (or `$SMIME_DIR`). Keep the CA in
its own directory outside this repository and run the tool from there.

## Layout

```
mailkey/
  ca.key.pem ca.crt.pem ca.cer ca.cnf ca-db/      the CA (ca.key.pem never leaves this directory)
  you@example.com/
    signing-iphone.20261030.{key.pem,csr.pem,crt.pem,p12}
    signing-thunderbird.20261030.*
    encryption-rsa.20261030.*
  bot@example.com/
    signing.20261030.*
    encryption-rsa.20261030.*
```

Each address has its own directory. File names are `KIND[-DEVICE].YYYYMMDD`
(UTC date of issue). `CERT` in the commands is this path without extension, as
`issue` prints it, e.g. `you@example.com/signing-iphone.20261030`; tab
completion works. `smime-ca list` shows every certificate with its expiry.

## Commands

| Command | Result |
| --- | --- |
| `init [--name NAME] [--days N]` | `ca.key.pem`, `ca.crt.pem`, `ca.cer` (DER, for import), `ca.cnf`, `ca-db/`. CA subject is `CN=NAME Mail Root CA`, valid 10 years, limited to email by `extendedKeyUsage=emailProtection`. |
| `issue signing\|encryption [--rsa] [--device DEVICE] [--email EMAIL] [--name NAME] [--days N]` | `EMAIL/KIND[-DEVICE].YYYYMMDD.{key.pem,csr.pem,crt.pem,p12}` signed by the CA, valid 1 year. `KIND` is `signing`, `encryption` (EC) or `encryption-rsa` (`--rsa`, RSA 3072). `--device` (e.g. `iphone`) names the device in the file names and the `.p12` friendly name only, not in the certificate. `EMAIL` is `--email` or `SMIME_EMAIL`. Refused if the CA expires earlier. |
| `export-p12 CERT [--legacy]` | `CERT.p12`, or `CERT-legacy.p12` with SHA-1/3DES. Never for `ca`. |
| `export-key CERT` | Unencrypted PKCS#8 PEM of the key on stdout, to be piped straight into the service that needs it. Refuses to write to a terminal and never exports `ca`. |
| `cert-mail CERT [--encryption-cert CERT] [--to EMAIL] [--subject TEXT]` | Message signed with `CERT` on stdout: `From` is the address in `CERT`, `To` is `--to` or `SMIME_EMAIL`. The signature carries `CERT`, `ca.crt.pem` and the `--encryption-cert` for the same address. A non-ASCII subject is RFC 2047 encoded. |
| `list` | Serial, subject, expiry, SAN and key usage of every `*.crt.pem` in the directory and in `EMAIL/`, marked `valid` or `EXPIRED`. |

`issue` asks for the CA passphrase (checked immediately), a new key passphrase
and a `.p12` export passphrase (empty = same as the key). All prompts come
before any file is written. Existing files are never overwritten, so the same
kind of certificate for the same address and device can be issued once a day.

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

## Which keys go where

- **Signing: one key per device.** Each device signs with its own key
  (`--device iphone`, `--device thunderbird`), so a lost device does not expose
  the others. Recipients accept any of them: all are issued by the same CA for
  the same address.
- **Encryption: one key per address, on every device.** Senders encrypt to one
  certificate, so every device that reads your mail needs the same encryption
  key. Use RSA (`--rsa`) as long as an iPhone must read the mail (see
  [Apple Mail](#apple-mail)).
- **Keep every old encryption key** (`EMAIL/encryption*.key.pem` and `.p12`),
  also after it expires: mail encrypted to it can only be read with it. Old
  signing keys can be deleted once replaced.

The examples below assume:

```bash
cd ~/mailkey
export SMIME_EMAIL=you@example.com SMIME_NAME='Your Name'
DAY=$(date -u +%Y%m%d)    # the date issue puts in the file names (UTC), valid on the day of issue
```

## Tasks

### First setup

```bash
smime-ca init                                # the CA; asks for a new CA passphrase
smime-ca issue signing --device thunderbird  # one per device
smime-ca issue signing --device iphone
smime-ca issue encryption --rsa              # one per address, installed everywhere
```

Then on each device:

1. Install `ca.cer` and trust it for email (see [Using the certificates](#using-the-certificates)).
2. Install that device's `signing-DEVICE.*.p12` and the `encryption-rsa.*.p12`.
3. Select them in the account settings: Thunderbird → Account Settings →
   End-To-End Encryption → S/MIME: "Personal certificate for digital signing"
   and "… for encryption". If Thunderbird offers to use one certificate for
   both, decline. iPhone → Settings → Apps → Mail → Mail Accounts → account →
   Account → Advanced: **Sign** and **Encrypt by Default**.
4. Send yourself a signed and encrypted message and open it on every device.

### New device

```bash
smime-ca issue signing --device ipad
```

Install `ca.cer`, the new `signing-ipad.*.p12` and the **existing**
`encryption-rsa.*.p12` (the newest one, see `smime-ca list`); select them as in
step 3 above.

### Lost or compromised device

Stop using its signing key: issue a new one for the replacement device. There
is no revocation (see [No revocation](#no-revocation)): the old certificate
stays valid until it expires. If the device also held the encryption key,
rotate the encryption key as below.

### Yearly rotation

Certificates are valid for one year; `smime-ca list` shows each expiry date
(`notAfter`).
Rotate before expiry:

```bash
smime-ca issue signing --device thunderbird
smime-ca issue signing --device iphone
smime-ca issue encryption --rsa
```

1. Install the new `.p12` files on every device and select them in the
   account settings.
2. Keep the old encryption key installed in Thunderbird (and on the iPhone, if
   it should read old mail) and in this directory: old mail needs it.
3. Rotate the bot certificates (below) and update the bot.

### Bot certificates

A bot that signs its mail and receives encrypted mail gets two certificates,
like a person: one key signs, the other decrypts. With a single RSA key, a bot
that leaks whether decryption failed would also let an attacker sign as the bot
([ROBOT](https://robotattack.org/)). Use `--rsa` for the encryption key if
iPhones must encrypt mail to the bot.

```bash
BOT=bot@example.com
smime-ca issue signing --email "$BOT" --name 'Mail Bot'
smime-ca issue encryption --rsa --email "$BOT" --name 'Mail Bot'

# the bot cannot type a passphrase: pipe the unencrypted keys into its secret
# store (replace the command after |); never save them to a file
smime-ca export-key "$BOT/signing.$DAY" | <command that stores the bot's signing key>
smime-ca export-key "$BOT/encryption-rsa.$DAY" | <command that stores the bot's encryption key>

# the bot also needs its certificates and the CA certificate
ls "$BOT/signing.$DAY.crt.pem" "$BOT/encryption-rsa.$DAY.crt.pem" ca.crt.pem

# a signed message that carries both bot certificates and ca.crt.pem
smime-ca cert-mail "$BOT/signing.$DAY" \
  --encryption-cert "$BOT/encryption-rsa.$DAY" --to "$SMIME_EMAIL" > bot.eml
```

Always pass `--email`: without it the certificate gets `SMIME_EMAIL`, your own
address. To see a key on screen instead, pipe it through `cat` and clear the
terminal afterwards. Opening `bot.eml` in Thunderbird (e.g. after copying it
into a mailbox folder) lets it install the bot's certificates, so it can
encrypt mail to the bot [inferred, not tested]. **Apple Mail cannot use
`bot.eml` for that**: `openssl cms` does not add the
`SMIMEEncryptionKeyPreference` attribute, so Apple Mail takes the bot's
signing certificate for encryption (see [Apple Mail](#apple-mail)). An iPhone
gets the bot's encryption certificate from a reply of the bot that carries
the attribute.

What the bot must do with these keys is in [Bot requirements](#bot-requirements).

### New CA

Create a new CA when the old one expires, its key may be compromised, or it
lacks `extendedKeyUsage=emailProtection` (hand-made CAs). A new CA means new
certificates for everyone, so switch over in steps:

1. Create it in a **new directory**; never run `init` over the old one (it
   refuses anyway). On an offline machine copy `smime-ca.sh` of the pinned
   commit and run it with `bash`.
   ```bash
   mkdir ~/mailkey-2027 && cd ~/mailkey-2027
   smime-ca init
   ```
2. Issue all certificates again from the new directory (first setup, bot).
3. Install the new `ca.cer` on every device **next to** the old one, and give
   the bot both CA certificates.
4. Switch devices and bot to the new certificates; test as in first setup.
5. Keep the old CA directory, with its encryption keys, for reading old mail.
   Remove trust in the old CA when its certificates have expired (or at once if
   its key is compromised).

## Using the certificates

1. Import `ca.cer` into the mail client (or OS keychain) and trust it for
   email only, e.g. in macOS Keychain set just "Secure Mail (S/MIME)" to
   "Always Trust". Correspondents need it too to validate your signatures.
   Whoever trusts the CA for everything would also accept TLS certificates
   signed with its key. CAs created by `init` carry
   `extendedKeyUsage=emailProtection`, which limits them to email in clients
   that enforce it; CAs made before that (or by hand) do not. On an iPhone,
   installing the `ca.cer` profile is one step; "Full Trust" (Settings →
   General → About → Certificate Trust Settings) additionally trusts it for
   TLS ([Apple](https://support.apple.com/en-us/102390)).
2. Import the `.p12` files. If the importer reports a wrong password for a
   correct one, try `export-p12 CERT --legacy`. If that file is rejected too,
   delete it and lower the iteration count to the classic PKCS#12 default:
   `KDF_ITER=2048 smime-ca export-p12 CERT --legacy`.
   Fewer iterations make guessing the `.p12` passphrase cheaper, so use a
   strong one and delete the file after import.

## Apple Mail

Tested on an iPhone with iOS 26 (October 2026):

| Encrypted with | Opens in Apple Mail |
| --- | --- |
| RSA PKCS#1 v1.5 (`rsaEncryption`), AES-256-CBC, MIME entity inside | yes |
| RSA-OAEP (SHA-1, SHA-256, SHA-512) | no |
| EC, as Thunderbird encrypts it (`dhSinglePass-stdDH-sha256kdf`/`sha384kdf`) | no |
| anything without a MIME entity inside ([RFC 8551 §3.3](https://www.rfc-editor.org/rfc/rfc8551#section-3.3)) | no |

This matches Apple's source code (RSA decryption hard-wired to PKCS#1 v1.5,
[crypto-embedded.c](https://github.com/apple-oss-distributions/Security/blob/Security-61901.101.4/libsecurity_smime/lib/crypto-embedded.c#L508-L519)),
[Indeno](https://inside.indeno.at/apple-mail-kann-keine-s-mime-nachrichten-mit-rsaes-oaep-entschlusseln/)
and [SEPPmail](https://docs.seppmail.com/en/09_ht_encryption_applemail-smime-rsaes-oaep.html).
Thunderbird encrypts for RSA certificates with PKCS#1 v1.5
([NSS](https://github.com/nss-dev/nss/blob/master/lib/smime/cmspubkey.c#L25-L89)),
hence `--rsa` for encryption.

Other findings:

- "Install a profile containing your encryption identity" appears for any
  failure: missing key, unsupported algorithm or a malformed message.
- To encrypt to someone, Apple Mail needs that person's certificate from a
  signed message ([Apple](https://support.apple.com/en-us/102245)). On iOS 26
  the certificate shows up only after editing the sender's contact, e.g. adding
  a space to Notes ([MacRumors](https://forums.macrumors.com/threads/s-mime-ios-26.2467497/)).
- Apple Mail takes the encryption certificate a signature points to with the
  `SMIMEEncryptionKeyPreference` attribute
  ([RFC 8551 §2.5.3](https://www.rfc-editor.org/rfc/rfc8551#section-2.5.3));
  without it, it uses the **signing** certificate for encryption
  ([cmssiginfo.c](https://github.com/apple-oss-distributions/Security/blob/Security-61901.101.4/OSX/libsecurity_smime/lib/cmssiginfo.c#L1633-L1696)).
  Thunderbird adds the attribute
  ([nsCMS.cpp](https://github.com/mozilla/releases-comm-central/blob/master/mailnews/extensions/smime/nsCMS.cpp#L1358-L1379)),
  so separate signing and encryption certificates work between Thunderbird
  and an iPhone (tested). `openssl cms -sign`, and so `cert-mail`, does not.
- PKCS#1 v1.5 and AES-CBC are the weakest options S/MIME still requires
  ("MUST-", [RFC 8551 §2.3, §2.7](https://www.rfc-editor.org/rfc/rfc8551#section-2.3)).
  Reduce the attack surface: no read receipts, no auto-replies, no remote
  content in mail clients ([EFAIL](https://efail.de/)).

Repeat these tests after major iOS updates; if OAEP or AES-GCM start to work,
prefer them.

## Bot requirements

What a mail bot using these certificates must do, so that iPhones and
Thunderbird can talk to it:

- Its replies are signed (S/MIME `multipart/signed`), then encrypted to the
  author's encryption certificate taken from the author's signature.
- Encryption: `EnvelopedData`, key transport `rsaEncryption` (PKCS#1 v1.5,
  never RSA-OAEP), content AES-256-CBC, a MIME entity inside.
- Its signature carries its signing and encryption certificates and the CA,
  and **must** have the `SMIMEEncryptionKeyPreference` attribute pointing to
  its encryption certificate
  ([RFC 8551 §2.5.3](https://www.rfc-editor.org/rfc/rfc8551#section-2.5.3)):
  without it Apple Mail encrypts to the signing certificate and fails. The
  OpenSSL command line cannot add it; the signing library must.
- It accepts mail encrypted to its encryption certificate and processes it only
  if signed by a certificate of this CA for the `From` address.
- Every rejected message gets the same answer whatever the reason (decryption,
  signature, sender), and nothing is sent before the signature is verified:
  otherwise the bot becomes an oracle for attacks on PKCS#1 v1.5
  ([RFC 3218](https://www.rfc-editor.org/rfc/rfc3218)).

## No revocation

The CA publishes no CRL, so a certificate cannot be revoked: it stays valid
for everyone who trusts the CA until it expires. If a certificate's key is
compromised, either accept that until expiry or create a new CA (see
[New CA](#new-ca)) and reissue all certificates. If the CA key is compromised,
a new CA is the only option.

## Notes

- Passphrases are passed to OpenSSL through file descriptors, not command line
  arguments or environment variables.
- New files are created with `umask 077` in a temporary directory and moved
  into place when complete (see the `issue` exception above).
- Certificates made before the per-address layout (files directly in the CA
  directory, e.g. `encryption.crt.pem`) keep working: pass their name as `CERT`.
- `.gitignore` excludes keys, certificates and CA state in case the tool is run
  inside the repository.
