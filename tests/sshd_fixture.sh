#!/usr/bin/env bash

# Written by Simon Josefsson

# Start sshd, invoke parameters, saving exit code, kill sshd, and
# return exit code.

if [ -n "$1" ]; then
  cmd="$*"
else
  cmd="${cmd:-./test-ssh}"
fi
srcdir="${srcdir:-$PWD}"
SSHD="${SSHD:-/usr/sbin/sshd}"

[[ "$(uname)" = *'_NT'* ]] && SSHD="$(cygpath -u "${SSHD}")"

srcdir="$(cd "$srcdir" || exit; pwd)"

# for our test clients:
[ -z "$PRIVKEY" ] && export PRIVKEY="$srcdir/key_rsa"
[ -z "$PUBKEY" ]  && export PUBKEY="$srcdir/key_rsa.pub"
cakeys="$srcdir/ca_main.pub"

if [ -n "$DEBUG" ]; then
  libssh2_sshd_params="-d -d"
fi

cat \
  "$srcdir/openssh_server/ca_ecdsa.pub" \
  "$srcdir/openssh_server/ca_rsa.pub" \
  > "$cakeys"

chmod go-rwx \
  "$srcdir"/openssh_server/ssh_host_* \
  "$cakeys"

export OPENSSH_NO_DOCKER=1

# shellcheck disable=SC2086
"$SSHD" \
  -f "$srcdir/openssh_server/sshd_config" \
  -o 'Port 4711' \
  -h "$srcdir/openssh_server/ssh_host_rsa_key" \
  -h "$srcdir/openssh_server/ssh_host_ecdsa_key" \
  -h "$srcdir/openssh_server/ssh_host_ed25519_key" \
  -o "AuthorizedKeysFile ${PUBKEY} $srcdir/key_dsa.pub $srcdir/key_rsa.pub $srcdir/key_rsa_encrypted.pub $srcdir/key_rsa_openssh.pub $srcdir/key_ed25519.pub $srcdir/key_ed25519_encrypted.pub $srcdir/key_ecdsa.pub" \
  -o "TrustedUserCAKeys $cakeys" \
  -D \
  $libssh2_sshd_params &
sshdpid=$!

trap 'kill "${sshdpid}"; echo signal killing sshd; exit 1;' EXIT

: "started sshd (${sshdpid})"

sleep 3

: "Invoking '$cmd'..."
eval "$cmd"
ec=$?
: "Self-test exit code $ec"

rm -f "$cakeys"

: "killing sshd (${sshdpid})"
kill "${sshdpid}" > /dev/null 2>&1
trap '' EXIT
exit "$ec"
