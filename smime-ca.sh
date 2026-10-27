#!/usr/bin/env bash
# Personal S/MIME CA: EC P-256 keys, PKCS#8 and PKCS#12 protected with
# AES-256-CBC + PBKDF2-HMAC-SHA256. Requires OpenSSL 3.x (macOS /usr/bin/openssl
# is LibreSSL and will not work).
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
  $PROG issue encryption|signing [LABEL] [--name NAME] [--email EMAIL] [--days N]
  $PROG list

init   creates ca.key.pem, ca.crt.pem, ca.cer (DER, for import), ca.cnf, ca-db/.
issue  creates PROFILE[-LABEL].{key.pem,csr.pem,crt.pem,p12}, signed by the CA.
       Existing files are never overwritten: use a LABEL for a second cert of
       the same profile (e.g. "issue signing thunderbird", "issue encryption 2027").
list   shows every *.crt.pem in the directory.

Environment:
  SMIME_DIR    working directory (default: current directory)
  SMIME_NAME   CN of the certificates; CA gets "NAME Mail Root CA"
  SMIME_EMAIL  address put into subjectAltName
  OPENSSL      openssl binary (default: openssl; must be OpenSSL 3.x)
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
	case $("$OPENSSL" version 2>/dev/null) in
	"OpenSSL 3."*) ;;
	*) die "need OpenSSL 3.x, got '$("$OPENSSL" version 2>&1 || true)'; set OPENSSL=/path/to/openssl" ;;
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

check_email() {
	[[ $1 =~ ^[^@[:space:],\$]+@[^@[:space:],\$]+$ ]] || die "bad email '$1': set SMIME_EMAIL or pass --email"
}

check_days() {
	[[ $1 =~ ^[1-9][0-9]*$ ]] || die "bad --days: $1"
}

# new_key OUT PASSPHRASE -- EC P-256 key, encrypted PKCS#8
new_key() {
	"$OPENSSL" genpkey \
		-algorithm EC \
		-pkeyopt ec_paramgen_curve:P-256 \
		-pkeyopt ec_param_enc:named_curve |
		"$OPENSSL" pkcs8 \
			-topk8 \
			-v2 aes-256-cbc \
			-v2prf hmacWithSHA256 \
			-iter "$KDF_ITER" \
			-passout fd:3 \
			-out "$1" \
			3< <(printf '%s\n' "$2")
}

# Files are created in a private staging directory and moved into place only
# after every step succeeded, so a failure never leaves half-made files behind.
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
	local profile='' label='' name=$SMIME_NAME email=$SMIME_EMAIL days=$CERT_DAYS
	local key_usage base f ca_pass key_pass p12_pass
	local -a verify_purpose=()
	while [ $# -gt 0 ]; do
		case $1 in
		--name) [ $# -ge 2 ] || die "--name needs a value"; name=$2; shift 2 ;;
		--email) [ $# -ge 2 ] || die "--email needs a value"; email=$2; shift 2 ;;
		--days) [ $# -ge 2 ] || die "--days needs a value"; days=$2; shift 2 ;;
		-*) die "unknown option: $1" ;;
		*)
			if [ -z "$profile" ]; then
				profile=$1
			elif [ -z "$label" ]; then
				label=$1
			else
				die "unexpected argument: $1"
			fi
			shift
			;;
		esac
	done

	case $profile in
	encryption) key_usage=keyAgreement ;;
	signing) key_usage=digitalSignature; verify_purpose=(-purpose smimesign) ;;
	"") die "profile required: encryption or signing" ;;
	*) die "unknown profile '$profile': encryption or signing" ;;
	esac
	[ -z "$label" ] || [[ $label =~ ^[A-Za-z0-9._-]+$ ]] || die "label may contain only A-Z a-z 0-9 . _ -"
	check_name "$name"
	check_email "$email"
	check_days "$days"

	for f in ca.key.pem ca.crt.pem ca.cnf ca-db/index.txt ca-db/serial; do
		[ -e "$f" ] || die "$SMIME_DIR/$f not found: run '$PROG init' first or set SMIME_DIR"
	done
	base=$profile${label:+-$label}
	for f in "$base".key.pem "$base".csr.pem "$base".crt.pem "$base".p12; do
		[ ! -e "$f" ] || die "$SMIME_DIR/$f already exists: pick another LABEL"
	done

	read_secret ca_pass "CA key passphrase"
	"$OPENSSL" pkey -in ca.key.pem -passin fd:3 -noout 3< <(printf '%s\n' "$ca_pass") 2>/dev/null ||
		die "wrong CA key passphrase"
	read_secret key_pass "New $base key passphrase" confirm
	[ -n "$key_pass" ] || die "empty passphrase"
	read_secret p12_pass "$base.p12 export passphrase (Enter = same as key)" confirm
	[ -n "$p12_pass" ] || p12_pass=$key_pass

	make_stage
	new_key "$STAGE/$base.key.pem" "$key_pass"
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

	"$OPENSSL" verify \
		-x509_strict \
		-CAfile ca.crt.pem \
		-no-CApath \
		-no-CAstore \
		${verify_purpose[@]+"${verify_purpose[@]}"} \
		-verify_email "$email" \
		"$STAGE/$base.crt.pem" >/dev/null

	"$OPENSSL" pkcs12 \
		-export \
		-inkey "$STAGE/$base.key.pem" \
		-in "$STAGE/$base.crt.pem" \
		-certfile ca.crt.pem \
		-name "$email $profile${label:+ $label}" \
		-keypbe AES-256-CBC \
		-certpbe AES-256-CBC \
		-macalg sha256 \
		-iter "$KDF_ITER" \
		-passin fd:3 \
		-passout fd:4 \
		-out "$STAGE/$base.p12" \
		3< <(printf '%s\n' "$key_pass") \
		4< <(printf '%s\n' "$p12_pass")

	for f in "$base".key.pem "$base".csr.pem "$base".crt.pem "$base".p12; do
		mv "$STAGE/$f" "$f"
	done
	"$OPENSSL" x509 -in "$base.crt.pem" -noout -serial -subject -dates -ext subjectAltName,keyUsage
	printf 'Created %s.{key.pem,csr.pem,crt.pem,p12}\n' "$base"
}

cmd_list() {
	local f state
	for f in *.crt.pem; do
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
	list) [ $# -eq 0 ] || die "list takes no arguments"; cmd_list ;;
	*) die "unknown command: $cmd (see $PROG --help)" ;;
	esac
}

main "$@"
