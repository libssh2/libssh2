# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

# Shared between CMakeLists.txt and Makefile.am

# Keep this list sorted
#
# NOTE: test_auth_keyboard_info_request does not use the network, but when
#       run as Windows standalone test, it intermittently fails on GHA with:
#         `Terminate batch job (Y/N)?`
DOCKER_TESTS = \
  test_aa_warmup \
  test_agent_forward_ok \
  test_auth_keyboard_fail \
  test_auth_keyboard_ok \
  test_auth_password_fail_password \
  test_auth_password_fail_username \
  test_auth_password_ok \
  test_auth_pubkey_fail \
  test_auth_pubkey_ok_dsa \
  test_auth_pubkey_ok_ecdsa_openssh \
  test_auth_pubkey_ok_ecdsa_openssh_encrypted \
  test_auth_pubkey_ok_ecdsa_openssh_signed \
  test_auth_pubkey_ok_ecdsa_pem \
  test_auth_pubkey_ok_ecdsa_pem_encrypted \
  test_auth_pubkey_ok_ecdsa_pkcs8 \
  test_auth_pubkey_ok_ecdsa_pkcs8_encrypted \
  test_auth_pubkey_ok_ed25519_openssh \
  test_auth_pubkey_ok_ed25519_openssh_encrypted \
  test_auth_pubkey_ok_ed25519_openssh_mem \
  test_auth_pubkey_ok_ed25519_openssh_signed \
  test_auth_pubkey_ok_ed25519_pkcs8 \
  test_auth_pubkey_ok_ed25519_pkcs8_encrypted \
  test_auth_pubkey_ok_rsa_openssh \
  test_auth_pubkey_ok_rsa_openssh_encrypted \
  test_auth_pubkey_ok_rsa_pem \
  test_auth_pubkey_ok_rsa_pem_encrypted \
  test_auth_pubkey_ok_rsa_pem_sha2_512_signed \
  test_auth_pubkey_ok_rsa_pem_signed \
  test_auth_pubkey_ok_rsa_pkcs8 \
  test_auth_pubkey_ok_rsa_pkcs8_encrypted \
  test_exit_status \
  test_hostkey_hash \
  test_read

STANDALONE_TESTS =

SSHD_TESTS = \
  test_ssh2 \
  test_auth_pubkey_ok_ed25519_openssh

# Programs of the above that use internal libssh2 functions so they need
# to be statically linked against libssh2
DOCKER_TESTS_STATIC = \
  test_auth_keyboard_info_request \
  test_hostkey

STANDALONE_TESTS_STATIC = \
  test_simple

# Copy of the above for Makefile.am.
# Is there a way to reuse the lists above?
test_auth_keyboard_info_request_LDFLAGS = -static
test_hostkey_LDFLAGS = -static
test_simple_LDFLAGS = -static

librunner_la_SOURCES = \
  runner.c runner.h \
  session_fixture.c session_fixture.h \
  openssh_fixture.c openssh_fixture.h

EXTRA_DIST = \
  .checksrc \
  CMakeLists.txt \
  keys-dump.sh \
  keys-generate.sh \
  keys/ca_host_ecdsa \
  keys/ca_host_ecdsa.pub \
  keys/ca_host_ed25519 \
  keys/ca_host_ed25519.pub \
  keys/ca_host_rsa \
  keys/ca_host_rsa.pub \
  keys/ca_user_ecdsa \
  keys/ca_user_ecdsa.pub \
  keys/ca_user_ed25519 \
  keys/ca_user_ed25519.pub \
  keys/ca_user_rsa \
  keys/ca_user_rsa.pub \
  keys/id_dsa \
  keys/id_dsa.pub \
  keys/id_dsa_wrong \
  keys/id_dsa_wrong.pub \
  keys/id_ecdsa_openssh \
  keys/id_ecdsa_openssh.pub \
  keys/id_ecdsa_openssh_encrypted \
  keys/id_ecdsa_openssh_encrypted.pub \
  keys/id_ecdsa_openssh_signed \
  keys/id_ecdsa_openssh_signed-cert.pub \
  keys/id_ecdsa_openssh_signed.pub \
  keys/id_ecdsa_pem \
  keys/id_ecdsa_pem.pub \
  keys/id_ecdsa_pem_encrypted \
  keys/id_ecdsa_pem_encrypted.pub \
  keys/id_ecdsa_pkcs8 \
  keys/id_ecdsa_pkcs8.pub \
  keys/id_ecdsa_pkcs8_encrypted \
  keys/id_ecdsa_pkcs8_encrypted.pub \
  keys/id_ed25519_openssh \
  keys/id_ed25519_openssh.pub \
  keys/id_ed25519_openssh_encrypted \
  keys/id_ed25519_openssh_encrypted.pub \
  keys/id_ed25519_openssh_signed \
  keys/id_ed25519_openssh_signed-cert.pub \
  keys/id_ed25519_openssh_signed.pub \
  keys/id_ed25519_pkcs8 \
  keys/id_ed25519_pkcs8.pub \
  keys/id_ed25519_pkcs8_encrypted \
  keys/id_ed25519_pkcs8_encrypted.pub \
  keys/id_rsa_openssh \
  keys/id_rsa_openssh.pub \
  keys/id_rsa_openssh_encrypted \
  keys/id_rsa_openssh_encrypted.pub \
  keys/id_rsa_pem \
  keys/id_rsa_pem.pub \
  keys/id_rsa_pem_encrypted \
  keys/id_rsa_pem_encrypted.pub \
  keys/id_rsa_pem_sha2_512_signed \
  keys/id_rsa_pem_sha2_512_signed-cert.pub \
  keys/id_rsa_pem_sha2_512_signed.pub \
  keys/id_rsa_pem_signed \
  keys/id_rsa_pem_signed.pub \
  keys/id_rsa_pem_signed-cert.pub \
  keys/id_rsa_pkcs8 \
  keys/id_rsa_pkcs8.pub \
  keys/id_rsa_pkcs8_encrypted \
  keys/id_rsa_pkcs8_encrypted.pub \
  openssh_server/Dockerfile \
  openssh_server/authorized_keys \
  openssh_server/ca_user_keys.pub \
  openssh_server/ssh_host_ecdsa_key \
  openssh_server/ssh_host_ecdsa_key-cert.pub \
  openssh_server/ssh_host_ecdsa_key.pub \
  openssh_server/ssh_host_ed25519_key \
  openssh_server/ssh_host_ed25519_key-cert.pub \
  openssh_server/ssh_host_ed25519_key.pub \
  openssh_server/ssh_host_rsa_key \
  openssh_server/ssh_host_rsa_key-cert.pub \
  openssh_server/ssh_host_rsa_key.pub \
  openssh_server/sshd_config \
  test_read_algos.test \
  test_read_algos.txt \
  test_sshd.test
