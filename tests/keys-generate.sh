#!/bin/sh
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

set -eu

# Generate test keys

# tests/openssh_server

[ -d openssh_server ] || mkdir openssh_server
rm openssh_server/*_key || true

ssh-keygen -t rsa     -b 2048 -N ''          -m PEM     -C ''                        -f 'openssh_server/ssh_host_rsa_key'
ssh-keygen -t ecdsa   -b  256 -N ''          -m PEM     -C ''                        -f 'openssh_server/ssh_host_ecdsa_key'
ssh-keygen -t ed25519         -N ''          -m RFC4716 -C ''                        -f 'openssh_server/ssh_host_ed25519_key'

rm openssh_server/ca_* || true

ssh-keygen -t rsa     -b 3072 -N ''          -m RFC4716 -C 'ca_rsa'                  -f 'openssh_server/ca_rsa'
ssh-keygen -t ecdsa   -b  521 -N ''          -m RFC4716 -C 'ca_ecdsa'                -f 'openssh_server/ca_ecdsa'

# tests

[ -d keys ] || mkdir keys
rm keys/id_* || true

pw='libssh2'
id='identity'
pr="${1:-libssh2}"

ssh-keygen -t dsa             -N ''          -m PEM     -C 'id_dsa'                     -f 'keys/id_dsa'               || touch 'keys/id_dsa.pub'
ssh-keygen -t dsa             -N ''          -m PEM     -C 'id_dsa_wrong'               -f 'keys/id_dsa_wrong'         || true # not to add to 'authorized_keys'

ssh-keygen -t rsa     -b 2048 -N ''          -m PEM     -C 'id_rsa'                     -f 'keys/id_rsa'
ssh-keygen -t rsa     -b 2048 -N "${pw}"     -m PEM     -C 'id_rsa_encrypted'           -f 'keys/id_rsa_encrypted'
ssh-keygen -t rsa     -b 2048 -N ''          -m RFC4716 -C ''                           -f 'keys/id_rsa_openssh'       # empty comment
ssh-keygen -t rsa     -b 2048 -N "${pw}"     -m RFC4716 -C 'id_rsa_aes256gcm'           -f 'keys/id_rsa_aes256gcm'     -Z aes256-gcm@openssh.com

ssh-keygen -t rsa     -b 4096 -N ''          -m RFC4716 -C 'id_rsa_signed'              -f 'keys/id_rsa_signed'
cp -p                                                                                      'keys/id_rsa_signed' \
                                                                                           'keys/id_rsa_signed_pem'
ssh-keygen -p                 -N ''          -m PEM                                     -f 'keys/id_rsa_signed_pem'
ssh-keygen -t ssh-rsa         -I "${id}" -n "${pr}"     -s 'openssh_server/ca_rsa'         'keys/id_rsa_signed.pub'

ssh-keygen -t rsa     -b 4096 -N ''          -m RFC4716 -C 'id_rsa_sha2_512_signed'     -f 'keys/id_rsa_sha2_512_signed'
cp -p                                                                                      'keys/id_rsa_sha2_512_signed' \
                                                                                           'keys/id_rsa_sha2_512_signed_pem'
ssh-keygen -p                 -N ''          -m PEM                                     -f 'keys/id_rsa_sha2_512_signed_pem'
ssh-keygen -t rsa-sha2-512    -I "${id}" -n "${pr}"     -s 'openssh_server/ca_rsa'         'keys/id_rsa_sha2_512_signed.pub'

ssh-keygen -t ecdsa   -b  384 -N ''          -m RFC4716 -C ''                           -f 'keys/id_ecdsa'             # empty comment
ssh-keygen -t ecdsa   -b  384 -N ''          -m RFC4716 -C 'id_ecdsa_signed'            -f 'keys/id_ecdsa_signed'
ssh-keygen                    -I "${id}" -n "${pr}"     -s 'openssh_server/ca_ecdsa'       'keys/id_ecdsa_signed.pub'

ssh-keygen -t ed25519         -N ''          -m RFC4716 -C 'id_ed25519'                 -f 'keys/id_ed25519'
ssh-keygen -t ed25519         -N "${pw}"     -m RFC4716 -C 'id_ed25519_encrypted'       -f 'keys/id_ed25519_encrypted' -Z aes256-ctr

cat \
  'keys/id_dsa.pub' \
  'keys/id_rsa.pub' \
  'keys/id_rsa_encrypted.pub' \
  'keys/id_rsa_openssh.pub' \
  'keys/id_rsa_aes256gcm.pub' \
  'keys/id_ecdsa.pub' \
  'keys/id_ed25519.pub' \
  'keys/id_ed25519_encrypted.pub' \
  > 'openssh_server/authorized_keys'

cat \
  'openssh_server/ca_rsa.pub' \
  'openssh_server/ca_ecdsa.pub' \
  > 'openssh_server/ca_user_keys.pub'

# tests/test_*.c

echo 'Add these public keys and hashes to:'
echo ' - test_hostkey.c'
echo ' - test_hostkey_hash.c'

for fn in ./openssh_server/*_key.pub; do
  pub="$(grep -a -o -E ' [A-Za-z0-9+/=]+' < "${fn}" | head -1 | cut -c 2-)"
  printf '====== %s\n' "${fn}"
  printf 'BASE64 %s\n' "${pub}"
  {
    printf 'MD5    %s\n' "$(printf '%s' "${pub}" | base64 -d | md5sum | tr -d ' -')"
    printf 'SHA1   %s\n' "$(printf '%s' "${pub}" | base64 -d | sha1sum | tr -d ' -')"
    printf 'SHA256 %s\n' "$(printf '%s' "${pub}" | base64 -d | sha256sum | tr -d ' -')"
  } | tr '[:lower:]' '[:upper:]'
  rm -f -- "${fn}"
done
