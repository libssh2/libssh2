#!/bin/sh -e

# Generate test keys

# tests/openssh_server

rm ./openssh_server/*_key || true

ssh-keygen -t rsa     -b 2048 -N ''          -m PEM -C ''                      -f 'openssh_server/ssh_host_rsa_key'
ssh-keygen -t ecdsa   -b  256 -N ''          -m PEM -C ''                      -f 'openssh_server/ssh_host_ecdsa_key'
ssh-keygen -t ed25519         -N ''                 -C ''                      -f 'openssh_server/ssh_host_ed25519_key'

rm ./openssh_server/ca_* || true

ssh-keygen -t ecdsa   -b  521 -N ''                 -C 'ca_ecdsa'              -f 'openssh_server/ca_ecdsa'
ssh-keygen -t rsa     -b 3072 -N ''                 -C 'ca_rsa'                -f 'openssh_server/ca_rsa'

# tests

rm './key_'* || true

pw='libssh2'
id='identity'
pr='libssh2'

ssh-keygen -t dsa             -N ''          -m PEM -C 'key_dsa'               -f 'key_dsa'
ssh-keygen -t dsa             -N ''          -m PEM -C 'key_dsa_wrong'         -f 'key_dsa_wrong'  # FIXME?

ssh-keygen -t rsa     -b 2048 -N ''          -m PEM -C 'key_rsa'               -f 'key_rsa'
ssh-keygen -t rsa     -b 2048 -N "${pw}"     -m PEM -C 'key_rsa_encrypted'     -f 'key_rsa_encrypted'
ssh-keygen -t rsa     -b 2048 -N ''                 -C 'key_rsa_openssh'       -f 'key_rsa_openssh'
ssh-keygen -t rsa     -b 4096 -N ''                 -C 'key_rsa_signed'        -f 'key_rsa_signed'
                   ssh-keygen -I "${id}" -n "${pr}" -s 'key_rsa_signed'           'key_rsa_signed'

ssh-keygen -t ecdsa   -b  384 -N ''                 -C 'key_ecdsa'             -f 'key_ecdsa'
ssh-keygen -t ecdsa   -b  384 -N ''                 -C 'key_ecdsa_signed'      -f 'key_ecdsa_signed'
                   ssh-keygen -I "${id}" -n "${pr}" -s 'key_ecdsa_signed'         'key_ecdsa_signed'

ssh-keygen -t ed25519         -N ''                 -C 'key_ed25519'           -f 'key_ed25519'
ssh-keygen -t ed25519         -N "${pw}"            -C 'key_ed25519_encrypted' -f 'key_ed25519_encrypted'

cat \
  'key_dsa.pub' \
  'key_rsa.pub' \
  'key_rsa_encrypted.pub' \
  'key_rsa_openssh.pub' \
  'key_ecdsa.pub' \
  'key_ed25519.pub' \
  'key_ed25519_encrypted.pub' \
  > openssh_server/authorized_keys

# tests/etc

rm etc/host* etc/user* || true

ssh-keygen -t rsa     -b 2048 -N ''          -m PEM -f 'etc/host'              -C 'etc_host_rsa'
ssh-keygen -t rsa     -b 2048 -N ''          -m PEM -f 'etc/user'              -C 'etc_user_rsa'

# tests/test_*.c

echo 'Add these public keys and hashes to:'
echo ' - test_hostkey.c'
echo ' - test_hostkey_hash.c'

for fn in ./openssh_server/*_key.pub; do
  pub="$(grep -a -o -E ' [A-Za-z0-9+/=]+' < "${fn}" | head -1 | cut -c 2-)"
  printf '====== %s\n' "${fn}"
  printf 'BASE64 %s\n' "${pub}"
  {
    printf 'MD5    %s\n' "$(printf '%s' "${pub}" | openssl base64 -d -A | openssl dgst -hex -md5)"
    printf 'SHA1   %s\n' "$(printf '%s' "${pub}" | openssl base64 -d -A | openssl dgst -hex -sha1)"
    printf 'SHA256 %s\n' "$(printf '%s' "${pub}" | openssl base64 -d -A | openssl dgst -hex -sha256)"
  } | tr '[:lower:]' '[:upper:]'
done
