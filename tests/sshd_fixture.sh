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

"$SSHD" -V

chmod go-rwx "$srcdir"/openssh_server/ssh_host_*

# shellcheck disable=SC2086
"$SSHD" \
  -f /dev/null \
  -h "$srcdir/openssh_server/ssh_host_rsa_key" \
  -h "$srcdir/openssh_server/ssh_host_ecdsa_key" \
  -h "$srcdir/openssh_server/ssh_host_ed25519_key" \
  -o 'Port 4711' \
  -o 'Protocol 2' \
  -o "AuthorizedKeysFile ${PUBKEY}" \
  -o 'UsePrivilegeSeparation no' \
  -o 'TrustedUserCAKeys /etc/ssh/ca_main.pub' \
  -o 'HostKeyAlgorithms +ssh-rsa' \
  -o 'PubkeyAcceptedKeyTypes +ssh-rsa,ssh-dss' \
  -o 'MACs +hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,hmac-md5,hmac-md5-96,umac-64@openssh.com,umac-128@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com' \
  -o 'Ciphers +3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com' \
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
