#!/usr/bin/env bash

# Written by Simon Josefsson

# Start sshd, invoke parameters, saving exit code, kill sshd, and
# return exit code.

if [ -n "$1" ]; then
  cmd="$*"
else
  cmd="${cmd:-./test_ssh2}"
fi

d="$(dirname "$0")"
d="$(cd "${d}" || exit; pwd)"  # sshd needs absolute paths

SSHD="${SSHD:-/usr/sbin/sshd}"
[[ "$(uname)" = *'_NT'* ]] && SSHD="$(cygpath -u "${SSHD}")"

# for our test clients:
[ -z "${PRIVKEY}" ] && export PRIVKEY="${d}/key_rsa"
[ -z "${PUBKEY}" ]  && export PUBKEY="${d}/key_rsa.pub"
cakeys="${d}/ca_main.pub"

if [ -n "${DEBUG}" ]; then
  libssh2_sshd_params="-d -d"
fi

cat \
  "${d}/openssh_server/ca_ecdsa.pub" \
  "${d}/openssh_server/ca_rsa.pub" \
  > "${cakeys}"

chmod go-rwx \
  "${d}"/openssh_server/ssh_host_* \
  "${cakeys}"

export OPENSSH_NO_DOCKER=1

# shellcheck disable=SC2086
"${SSHD}" \
  -f "${OPENSSH_SERVER_CONFIG:-${d}/openssh_server/sshd_config}" \
  -o "Port ${OPENSSH_SERVER_PORT:-4711}" \
  -h "${d}/openssh_server/ssh_host_rsa_key" \
  -h "${d}/openssh_server/ssh_host_ecdsa_key" \
  -h "${d}/openssh_server/ssh_host_ed25519_key" \
  -o "AuthorizedKeysFile ${PUBKEY} ${d}/key_dsa.pub ${d}/key_rsa.pub ${d}/key_rsa_encrypted.pub ${d}/key_rsa_openssh.pub ${d}/key_ed25519.pub ${d}/key_ed25519_encrypted.pub ${d}/key_ecdsa.pub" \
  -o "TrustedUserCAKeys ${cakeys}" \
  -D \
  ${libssh2_sshd_params} &
sshdpid=$!

trap 'kill "${sshdpid}"; echo signal killing sshd; exit 1;' EXIT

: "started sshd (${sshdpid})"

if [[ "$(uname)" = *'_NT'* ]]; then
  sleep 5
else
  sleep 3
fi

: "Invoking '${cmd}'..."
eval "${cmd}"
ec=$?
: "Self-test exit code ${ec}"

rm -f "${cakeys}"

: "killing sshd (${sshdpid})"
kill "${sshdpid}" > /dev/null 2>&1
trap '' EXIT
exit "${ec}"
