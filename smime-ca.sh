#!/usr/bin/env bash
# Personal S/MIME CA: EC P-256 keys (RSA 3072 on request for encryption),
# PKCS#8 and PKCS#12 protected with
# AES-256-CBC + PBKDF2-HMAC-SHA256. Requires OpenSSL 3 or newer (macOS
# /usr/bin/openssl is LibreSSL and will not work).
set -euo pipefail

OPENSSL=${OPENSSL:-openssl}
SMIME_DIR=${SMIME_DIR:-.}
SMIME_NAME=${SMIME_NAME:-}
SMIME_EMAIL=${SMIME_EMAIL:-}
KDF_ITER=${KDF_ITER:-600000}
CA_DAYS=${CA_DAYS:-3650}
CERT_DAYS=${CERT_DAYS:-365}

PROG=${0##*/}

usage() {
	cat <<EOF
Usage:
  $PROG init [--name NAME] [--days N]
  $PROG issue signing|encryption [--rsa] [--device DEVICE] [--email EMAIL] [--name NAME] [--days N]
  $PROG export-p12 CERT [--legacy]
  $PROG export-key CERT | COMMAND
  $PROG cert-mail CERT [--encryption-cert CERT] [--to EMAIL] [--subject TEXT] > mail.eml
  $PROG list

CERT is a certificate's path without extension, as printed by issue,
e.g. bot@example.com/signing.20261029 (tab completion works).

init        creates ca.key.pem, ca.crt.pem, ca.cer (DER, for import), ca.cnf, ca-db/.
issue       creates EMAIL/KIND[-DEVICE].YYYYMMDD.{key.pem,csr.pem,crt.pem,p12}, signed by the CA.
            KIND: signing (EC P-256, digitalSignature), encryption (EC P-256,
            keyAgreement) or, with --rsa, encryption-rsa (RSA 3072, keyEncipherment),
            for iOS Mail, which does not decrypt EC-encrypted mail from Thunderbird.
            EMAIL is --email or SMIME_EMAIL. Existing files are never overwritten.
            Signing and encryption use separate keys, also for a bot.
            --device names the device the key is for (e.g. iphone); it goes into
            the file names and the .p12 friendly name, not into the certificate.
export-p12  writes CERT.p12 again, e.g. after a failed issue; with --legacy writes
            CERT-legacy.p12 with SHA-1/3DES for importers that reject AES.
export-key  prints the private key as unencrypted PKCS#8 PEM to stdout, for
            services that cannot enter a passphrase. Refuses to print to a terminal:
            pipe it into the service that needs it.
cert-mail   prints a message signed with CERT to stdout (From: the address in CERT,
            To: --to or SMIME_EMAIL). The signature carries CERT, ca.crt.pem and,
            with --encryption-cert, the encryption certificate for the same address,
            so a mail client that opens the message can install them.
list        shows every *.crt.pem in the directory and in EMAIL/ subdirectories.

Environment:
  SMIME_DIR    working directory (default: current directory)
  SMIME_NAME   CN of the certificates; CA gets "NAME Mail Root CA"
  SMIME_EMAIL  your address: subjectAltName for issue, recipient for cert-mail
  OPENSSL      openssl binary (default: openssl; OpenSSL 3 or newer)
  KDF_ITER     PBKDF2 iterations for keys and .p12 (default: 600000)
  CA_DAYS      CA validity (default: 3650)
  CERT_DAYS    certificate validity (default: 365)
EOF
}

die() {
	printf '%s: %s\n' "$PROG" "$*" >&2
	exit 1
}

check_openssl() {
	local v
	v=$("$OPENSSL" version 2>/dev/null) || v=
	case $v in
	"OpenSSL "[3-9].* | "OpenSSL "[1-9][0-9].*) ;;
	*) die "need OpenSSL 3 or newer, got '${v:-nothing}'; set OPENSSL=/path/to/openssl" ;;
	esac
}

# read_secret VAR PROMPT [confirm]
read_secret() {
	local a b
	IFS= read -r -s -p "$2: " a || die "no input"
	[ -t 0 ] && echo >&2
	if [ -n "${3:-}" ]; then
		IFS= read -r -s -p "$2 (again): " b || die "no input"
		[ -t 0 ] && echo >&2
		[ "$a" = "$b" ] || die "passphrases do not match"
	fi
	printf -v "$1" '%s' "$a"
}

check_name() {
	[ -n "$1" ] || die "name is empty: set SMIME_NAME or pass --name"
	case $1 in *[/+=\\]*) die "name must not contain / + = or \\: $1" ;; esac
}

# check_email ADDRESS HINT -- the address is written into an OpenSSL config
# file, so only plain ASCII address characters are accepted.
check_email() {
	local re='^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$'
	[[ $1 =~ $re ]] || die "bad email '$1': $2"
}

check_base() {
	[[ $1 =~ ^([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+/)?[A-Za-z0-9._%+@-]+$ ]] ||
		die "bad certificate name '$1': use the path without extension, as printed by issue"
	[ "$1" != ca ] || die "refusing to use the CA key here"
}

# encode_subject TEXT -- mail header text; non-ASCII becomes an RFC 2047 word
encode_subject() {
	local LC_ALL=C
	case $1 in
	*[[:cntrl:]]*) die "subject must not contain control characters" ;;
	*[![:print:]]*) printf '=?UTF-8?B?%s?=' "$(printf '%s' "$1" | "$OPENSSL" base64 -A)" ;;
	*) printf '%s' "$1" ;;
	esac
}

need_files() {
	local f
	for f; do
		[ -e "$f" ] || die "$SMIME_DIR/$f not found"
	done
}

check_days() {
	[[ $1 =~ ^[1-9][0-9]*$ ]] || die "bad --days: $1"
}

# new_key OUT PASSPHRASE [rsa] -- EC P-256 or RSA 3072 key, encrypted PKCS#8
new_key() {
	local -a algorithm=(-algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve)
	[ -z "${3:-}" ] || algorithm=(-algorithm RSA -pkeyopt rsa_keygen_bits:3072)
	"$OPENSSL" genpkey "${algorithm[@]}" |
		"$OPENSSL" pkcs8 \
			-topk8 \
			-v2 aes-256-cbc \
			-v2prf hmacWithSHA256 \
			-iter "$KDF_ITER" \
			-passout fd:3 \
			-out "$1" \
			3< <(printf '%s\n' "$2")
}

check_key_pass() {
	"$OPENSSL" pkey -in "$1" -passin fd:3 -noout 3< <(printf '%s\n' "$2") 2>/dev/null ||
		die "wrong passphrase for $1"
}

# read_p12_pass VAR FILE KEY_PASSPHRASE
read_p12_pass() {
	local p
	read_secret p "$2 export passphrase (Enter = same as key)" confirm
	printf -v "$1" '%s' "${p:-$3}"
}

# cert_email CERT -- first email address of the certificate
cert_email() {
	local line=''
	"$OPENSSL" x509 -in "$1" -noout -email | { IFS= read -r line || true; printf '%s' "$line"; }
}

# verify_cert CERT EMAIL [PURPOSE]
verify_cert() {
	local -a purpose=()
	[ -z "${3:-}" ] || purpose=(-purpose "$3")
	"$OPENSSL" verify \
		-x509_strict \
		-CAfile ca.crt.pem \
		-no-CApath \
		-no-CAstore \
		${purpose[@]+"${purpose[@]}"} \
		-verify_email "$2" \
		"$1" >/dev/null
}

# make_p12 CERT KEY_PASSPHRASE P12_PASSPHRASE OUT [legacy]
make_p12() {
	local email
	local -a pbe=(-keypbe AES-256-CBC -certpbe AES-256-CBC -macalg sha256)
	# Older importers (e.g. Apple Keychain/iOS, Windows) may only understand
	# the PKCS#12 SHA-1/3DES scheme and report AES files as a wrong password.
	[ -z "${5:-}" ] || pbe=(-keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1)
	email=$(cert_email "$1.crt.pem")
	"$OPENSSL" pkcs12 \
		-export \
		-inkey "$1.key.pem" \
		-in "$1.crt.pem" \
		-certfile ca.crt.pem \
		-name "$email ${1##*/}" \
		"${pbe[@]}" \
		-iter "$KDF_ITER" \
		-passin fd:3 \
		-passout fd:4 \
		-out "$4" \
		3< <(printf '%s\n' "$2") \
		4< <(printf '%s\n' "$3")
}

# New files are created in a private staging directory and moved into place
# once they are complete, so a failure does not leave half-made files behind.
# Exception: after "openssl ca" has signed, the CA database already records the
# certificate, so issue keeps the key and certificate from that point on.
make_stage() {
	umask 077
	STAGE=$(mktemp -d "./.smime-ca.XXXXXX")
	trap 'rm -rf "$STAGE"' EXIT
}

cmd_init() {
	local name=$SMIME_NAME days=$CA_DAYS ca_pass f
	while [ $# -gt 0 ]; do
		case $1 in
		--name) [ $# -ge 2 ] || die "--name needs a value"; name=$2; shift 2 ;;
		--days) [ $# -ge 2 ] || die "--days needs a value"; days=$2; shift 2 ;;
		*) die "unknown argument: $1" ;;
		esac
	done
	check_name "$name"
	check_days "$days"
	for f in ca.key.pem ca.crt.pem ca.cer ca.cnf ca-db; do
		[ ! -e "$f" ] || die "$SMIME_DIR/$f already exists"
	done

	read_secret ca_pass "New CA key passphrase" confirm
	[ -n "$ca_pass" ] || die "empty passphrase"

	make_stage
	new_key "$STAGE/ca.key.pem" "$ca_pass"
	"$OPENSSL" req \
		-new -x509 \
		-config /dev/null \
		-key "$STAGE/ca.key.pem" \
		-passin fd:3 \
		-sha256 \
		-days "$days" \
		-utf8 \
		-subj "/CN=$name Mail Root CA" \
		-addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-addext "extendedKeyUsage=emailProtection" \
		-addext "subjectKeyIdentifier=hash" \
		-addext "authorityKeyIdentifier=keyid:always" \
		-out "$STAGE/ca.crt.pem" \
		3< <(printf '%s\n' "$ca_pass")
	"$OPENSSL" x509 -in "$STAGE/ca.crt.pem" -outform DER -out "$STAGE/ca.cer"

	mkdir -p "$STAGE/ca-db/newcerts"
	: >"$STAGE/ca-db/index.txt"
	"$OPENSSL" rand -hex 16 >"$STAGE/ca-db/serial"
	cat >"$STAGE/ca.cnf" <<'EOF'
[ca]
default_ca = local_ca

[local_ca]
dir = .
database = $dir/ca-db/index.txt
new_certs_dir = $dir/ca-db/newcerts
certificate = $dir/ca.crt.pem
private_key = $dir/ca.key.pem
serial = $dir/ca-db/serial

default_md = sha256
default_days = 365
policy = policy_local
unique_subject = no
copy_extensions = none

[policy_local]
commonName = supplied
EOF

	for f in ca.key.pem ca.crt.pem ca.cer ca.cnf ca-db; do
		mv "$STAGE/$f" "$f"
	done
	"$OPENSSL" x509 -in ca.crt.pem -noout -subject -dates -fingerprint -sha256
}

cmd_issue() {
	local profile='' name=$SMIME_NAME email=$SMIME_EMAIL days=$CERT_DAYS rsa='' device=''
	local key_usage purpose kind base f ca_pass key_pass p12_pass
	local -a outputs
	while [ $# -gt 0 ]; do
		case $1 in
		--name) [ $# -ge 2 ] || die "--name needs a value"; name=$2; shift 2 ;;
		--email) [ $# -ge 2 ] || die "--email needs a value"; email=$2; shift 2 ;;
		--rsa) rsa=1; shift ;;
		--device) [ $# -ge 2 ] || die "--device needs a value"; device=$2; shift 2 ;;
		--days) [ $# -ge 2 ] || die "--days needs a value"; days=$2; shift 2 ;;
		-*) die "unknown option: $1" ;;
		*) [ -z "$profile" ] || die "unexpected argument: $1"; profile=$1; shift ;;
		esac
	done

	case $profile in
	encryption)
		if [ -n "$rsa" ]; then
			# iOS Mail decrypts RSA (PKCS#1 v1.5) but not the EC key agreement
			# Thunderbird uses. Key management only, per the CA/B S/MIME BR.
			key_usage=keyEncipherment
			purpose=smimeencrypt
			kind='encryption-rsa'
		else
			# Verified without a purpose: OpenSSL's smimeencrypt purpose demands
			# keyEncipherment, which EC keys cannot have (they use keyAgreement).
			key_usage=keyAgreement
			purpose=''
			kind=encryption
		fi
		;;
	signing)
		[ -z "$rsa" ] || die "--rsa is only for encryption"
		key_usage=digitalSignature
		purpose=smimesign
		kind=signing
		;;
	"") die "profile required: signing or encryption" ;;
	*) die "unknown profile '$profile': signing or encryption" ;;
	esac
	check_name "$name"
	check_email "$email" "set SMIME_EMAIL or pass --email"
	check_days "$days"
	[ -z "$device" ] || [[ $device =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "--device may contain only a-z 0-9 -"
	kind=$kind${device:+-$device}

	for f in ca.key.pem ca.crt.pem ca.cnf ca-db/index.txt ca-db/serial; do
		[ -e "$f" ] || die "$SMIME_DIR/$f not found: run '$PROG init' first or set SMIME_DIR"
	done
	base=$email/$kind.$(date -u '+%Y%m%d')
	outputs=("$base.key.pem" "$base.csr.pem" "$base.crt.pem" "$base.p12")
	for f in "${outputs[@]}"; do
		[ ! -e "$f" ] || die "$SMIME_DIR/$f already exists: the $kind certificate for $email was already issued today"
	done
	"$OPENSSL" x509 -in ca.crt.pem -noout -checkend $((days * 86400)) >/dev/null ||
		die "the CA expires within $days days: lower --days or create a new CA"

	read_secret ca_pass "CA key passphrase"
	check_key_pass ca.key.pem "$ca_pass"
	read_secret key_pass "New $base key passphrase" confirm
	[ -n "$key_pass" ] || die "empty passphrase"
	read_p12_pass p12_pass "$base.p12" "$key_pass"

	make_stage
	mkdir -p "$STAGE/$email"
	new_key "$STAGE/$base.key.pem" "$key_pass" "$rsa"
	"$OPENSSL" req \
		-new \
		-config /dev/null \
		-key "$STAGE/$base.key.pem" \
		-passin fd:3 \
		-sha256 \
		-utf8 \
		-subj "/CN=$name" \
		-out "$STAGE/$base.csr.pem" \
		3< <(printf '%s\n' "$key_pass")

	cat >"$STAGE/ext.cnf" <<EOF
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,$key_usage
extendedKeyUsage = emailProtection
subjectAltName = email:$email
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF
	# SMIME_EMAIL in the environment: hand-made ca.cnf files may reference
	# $ENV::SMIME_EMAIL, and OpenSSL refuses to load them when it is unset.
	SMIME_EMAIL=$email "$OPENSSL" ca \
		-config ca.cnf \
		-extfile "$STAGE/ext.cnf" \
		-extensions leaf \
		-days "$days" \
		-in "$STAGE/$base.csr.pem" \
		-out "$STAGE/$base.crt.pem" \
		-passin fd:3 \
		-notext \
		-batch \
		3< <(printf '%s\n' "$ca_pass")

	# The CA database now records the certificate: keep key and certificate.
	mkdir -p "$email"
	for f in "$base.key.pem" "$base.csr.pem" "$base.crt.pem"; do
		mv "$STAGE/$f" "$f"
	done
	verify_cert "$base.crt.pem" "$email" "$purpose"
	make_p12 "$base" "$key_pass" "$p12_pass" "$STAGE/$base.p12" ||
		die "certificate issued, but $base.p12 failed; retry with: $PROG export-p12 $base"
	mv "$STAGE/$base.p12" "$base.p12"
	"$OPENSSL" x509 -in "$base.crt.pem" -noout -serial -subject -dates -ext subjectAltName,keyUsage
	printf 'Created %s\n' "${outputs[*]}"
}

cmd_export_p12() {
	local base='' legacy='' out key_pass p12_pass
	while [ $# -gt 0 ]; do
		case $1 in
		--legacy) legacy=1; shift ;;
		-*) die "unknown option: $1" ;;
		*) [ -z "$base" ] || die "unexpected argument: $1"; base=$1; shift ;;
		esac
	done
	[ -n "$base" ] || die "certificate name required, e.g. $PROG export-p12 you@example.com/encryption-rsa.20261029"
	check_base "$base"
	need_files "$base.key.pem" "$base.crt.pem" ca.crt.pem
	out=$base${legacy:+-legacy}.p12
	[ ! -e "$out" ] || die "$SMIME_DIR/$out already exists"

	read_secret key_pass "$base key passphrase"
	check_key_pass "$base.key.pem" "$key_pass"
	read_p12_pass p12_pass "$out" "$key_pass"

	make_stage
	mkdir -p "$STAGE/$(dirname "$out")"
	make_p12 "$base" "$key_pass" "$p12_pass" "$STAGE/$out" "$legacy"
	mv "$STAGE/$out" "$out"
	printf 'Created %s\n' "$out"
}

cmd_export_key() {
	local key_pass
	[ $# -eq 1 ] || die "usage: $PROG export-key CERT | COMMAND"
	check_base "$1"
	need_files "$1.key.pem"
	[ ! -t 1 ] || die "refusing to print an unencrypted private key to the terminal; pipe it into the service that needs it"
	read_secret key_pass "$1 key passphrase"
	check_key_pass "$1.key.pem" "$key_pass"
	"$OPENSSL" pkey -in "$1.key.pem" -passin fd:3 3< <(printf '%s\n' "$key_pass")
}

cmd_cert_mail() {
	local base='' encryption='' to=$SMIME_EMAIL subject='' from key_pass body message
	while [ $# -gt 0 ]; do
		case $1 in
		--encryption-cert) [ $# -ge 2 ] || die "--encryption-cert needs a value"; encryption=$2; shift 2 ;;
		--to) [ $# -ge 2 ] || die "--to needs a value"; to=$2; shift 2 ;;
		--subject) [ $# -ge 2 ] || die "--subject needs a value"; subject=$2; shift 2 ;;
		-*) die "unknown option: $1" ;;
		*) [ -z "$base" ] || die "unexpected argument: $1"; base=$1; shift ;;
		esac
	done
	[ -n "$base" ] || die "certificate name required, e.g. $PROG cert-mail bot@example.com/signing.20261029"
	check_base "$base"
	need_files "$base.key.pem" "$base.crt.pem" ca.crt.pem
	from=$(cert_email "$base.crt.pem")
	[ -n "$from" ] || die "$base.crt.pem has no email address"
	check_email "$to" "set SMIME_EMAIL or pass --to"
	verify_cert "$base.crt.pem" "$from" smimesign 2>/dev/null ||
		die "$base.crt.pem is not a valid signing certificate"
	if [ -n "$encryption" ]; then
		check_base "$encryption"
		need_files "$encryption.crt.pem"
		verify_cert "$encryption.crt.pem" "$from" 2>/dev/null ||
			die "$encryption.crt.pem is not a valid certificate for $from"
		case $("$OPENSSL" x509 -in "$encryption.crt.pem" -noout -ext keyUsage) in
		*"Key Encipherment"* | *"Key Agreement"*) ;;
		*) die "$encryption.crt.pem is not an encryption certificate" ;;
		esac
	fi
	subject=$(encode_subject "${subject:-S/MIME certificate of $from}")

	read_secret key_pass "$base key passphrase"
	check_key_pass "$base.key.pem" "$key_pass"

	body="This message is signed with the S/MIME certificate of $from.
Install the certificate from the signature details to send encrypted mail to $from."
	# Built in memory first, so a failure prints nothing.
	message=$(printf '%s\n' "$body" |
		"$OPENSSL" cms \
			-sign \
			-md sha256 \
			-signer "$base.crt.pem" \
			-inkey "$base.key.pem" \
			-passin fd:3 \
			-certfile <(cat ca.crt.pem ${encryption:+"$encryption.crt.pem"}) \
			-text \
			-from "$from" \
			-to "$to" \
			-subject "$subject" \
			3< <(printf '%s\n' "$key_pass"))
	printf 'Date: %s\nMessage-ID: <%s@%s>\n%s\n' \
		"$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')" \
		"$("$OPENSSL" rand -hex 16)" \
		"${from#*@}" \
		"$message"
}

cmd_list() {
	local f state
	for f in *.crt.pem */*.crt.pem; do
		[ -e "$f" ] || continue
		if "$OPENSSL" x509 -in "$f" -noout -checkend 0 >/dev/null; then state=valid; else state=EXPIRED; fi
		printf '== %s (%s)\n' "$f" "$state"
		"$OPENSSL" x509 -in "$f" -noout -serial -subject -enddate -ext subjectAltName,keyUsage
	done
}

main() {
	[ $# -gt 0 ] || { usage >&2; exit 2; }
	case $1 in -h | --help | help) usage; exit 0 ;; esac
	check_openssl
	cd "$SMIME_DIR" || die "cannot cd to $SMIME_DIR"
	local cmd=$1
	shift
	case $cmd in
	init) cmd_init "$@" ;;
	issue) cmd_issue "$@" ;;
	export-p12) cmd_export_p12 "$@" ;;
	export-key) cmd_export_key "$@" ;;
	cert-mail) cmd_cert_mail "$@" ;;
	list) [ $# -eq 0 ] || die "list takes no arguments"; cmd_list ;;
	*) die "unknown command: $cmd (see $PROG --help)" ;;
	esac
}

main "$@"
