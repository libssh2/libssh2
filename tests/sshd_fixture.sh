#!/usr/bin/env bash

# Written by Simon Josefsson

# Start sshd, invoke parameters, saving exit code, kill sshd, and
# return exit code.

if [ -n "$1" ]; then
  cmd="$*"
else
  cmd="${cmd:-./test-ssh}"
fi

SSHD="${SSHD:-/usr/sbin/sshd}"
[[ "$(uname)" = *'_NT'* ]] && SSHD="$(cygpath -u "${SSHD}")"

cd "$(dirname "$0")" || exit 1
pwd

# for our test clients:
[ -z "$PRIVKEY" ] && export PRIVKEY='key_rsa'
[ -z "$PUBKEY" ]  && export PUBKEY='key_rsa.pub'
cakeys='ca_main.pub'

if [ -n "$DEBUG" ]; then
  libssh2_sshd_params="-d -d"
fi

cat \
  'openssh_server/ca_ecdsa.pub' \
  'openssh_server/ca_rsa.pub' \
  > "$cakeys"

chmod go-rwx \
  openssh_server/ssh_host_* \
  "$cakeys"

export OPENSSH_NO_DOCKER=1

# shellcheck disable=SC2086
"$SSHD" \
  -f 'openssh_server/sshd_config' \
  -o 'Port 4711' \
  -h 'openssh_server/ssh_host_rsa_key' \
  -h 'openssh_server/ssh_host_ecdsa_key' \
  -h 'openssh_server/ssh_host_ed25519_key' \
  -o "AuthorizedKeysFile ${PUBKEY} key_dsa.pub key_rsa.pub key_rsa_encrypted.pub key_rsa_openssh.pub key_ed25519.pub key_ed25519_encrypted.pub key_ecdsa.pub" \
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
