#!/bin/sh

# Written by Simon Josefsson

# Start sshd, invoke parameters, saving exit code, kill sshd, and
# return exit code.

if [ -n "$1" ]; then
  cmd="$*"
else
  cmd="${cmd:-./test_ssh2${EXEEXT}}"
fi
srcdir="${srcdir:-$PWD}"
SSHD="${SSHD:-/usr/sbin/sshd}"

srcdir="$(cd "$srcdir" || exit; pwd)"

export PRIVKEY="$srcdir/etc/user"
export PUBKEY="$srcdir/etc/user.pub"

if [ -n "$DEBUG" ]; then
  libssh2_sshd_params="-d -d"
fi

chmod go-rwx "$srcdir"/etc/host*
# shellcheck disable=SC2086
"$SSHD" -f /dev/null -h "$srcdir/etc/host" \
  -o 'Port 4711' \
  -o 'Protocol 2' \
  -o "AuthorizedKeysFile $srcdir/etc/user.pub" \
  -o 'StrictModes no' \
  -D \
  $libssh2_sshd_params &
sshdpid=$!

trap 'kill "${sshdpid}"; echo signal killing sshd; exit 1;' EXIT

: "started sshd (${sshdpid})"

sleep 3

: "Invoking $cmd..."
eval "$cmd"
ec=$?
: "Self-test exit code $ec"

: "killing sshd (${sshdpid})"
kill "${sshdpid}" > /dev/null 2>&1
trap "" EXIT
exit "$ec"
