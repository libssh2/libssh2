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
export PRIVKEY="$srcdir/key_rsa"
export PUBKEY="$srcdir/key_rsa.pub"

if [ -n "$DEBUG" ]; then
  libssh2_sshd_params="-d -d"
fi

chmod go-rwx "$srcdir"/openssh_server/ssh_host*
# shellcheck disable=SC2086
"$SSHD" -f /dev/null -h "$srcdir/openssh_server/ssh_host_rsa_key" \
  -o 'Port 4711' \
  -o 'Protocol 2' \
  -o "AuthorizedKeysFile ${PUBKEY}" \
  -o 'StrictModes no' \
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

: "killing sshd (${sshdpid})"
kill "${sshdpid}" > /dev/null 2>&1
trap "" EXIT
exit "$ec"
