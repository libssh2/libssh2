SUBDIRS = ossfuzz

AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src -I$(top_srcdir)/include

ctests = simple$(EXEEXT)
TESTS = $(ctests) mansyntax.sh
check_PROGRAMS = $(ctests)

if SSHD
TESTS += ssh2.sh
check_PROGRAMS += ssh2
endif

INTEGRATION_TESTS = \
  test_warmup \
  test_agent_forward_ok \
  test_auth_keyboard_fail \
  test_auth_keyboard_info_request \
  test_auth_keyboard_ok \
  test_auth_password_fail_password \
  test_auth_password_fail_username \
  test_auth_password_ok \
  test_auth_pubkey_fail \
  test_auth_pubkey_ok_dsa \
  test_auth_pubkey_ok_ecdsa \
  test_auth_pubkey_ok_ecdsa_signed \
  test_auth_pubkey_ok_ed25519 \
  test_auth_pubkey_ok_ed25519_encrypted \
  test_auth_pubkey_ok_ed25519_mem \
  test_auth_pubkey_ok_rsa \
  test_auth_pubkey_ok_rsa_encrypted \
  test_auth_pubkey_ok_rsa_openssh \
  test_auth_pubkey_ok_rsa_signed \
  test_hostkey \
  test_hostkey_hash \
  test_read

# Integration tests using Docker
# Enable this once the tests are working
#TESTS += $(INTEGRATION_TESTS)
check_PROGRAMS += $(INTEGRATION_TESTS)
librunner_la_SOURCES = \
  runner.c runner.h \
  session_fixture.c session_fixture.h \
  openssh_fixture.c openssh_fixture.h
LDADD = librunner.la
check_LTLIBRARIES = librunner.la

# This program uses an internal libssh2 function so it needs to be statically
# linked against libssh2
test_auth_keyboard_info_request_LDFLAGS = -static

# This must be last in the list so it resolves symbols in previous libraries
LDADD += ../src/libssh2.la

TESTS_ENVIRONMENT = SSHD=$(SSHD) EXEEXT=$(EXEEXT)
TESTS_ENVIRONMENT += srcdir=$(top_srcdir)/tests builddir=$(top_builddir)/tests

EXTRA_DIST = \
  CMakeLists.txt \
  etc/host \
  etc/host.pub \
  etc/sshd_config \
  etc/user \
  etc/user.pub \
  key_dsa \
  key_dsa.pub \
  key_dsa_wrong \
  key_dsa_wrong.pub \
  key_ecdsa \
  key_ecdsa.pub \
  key_ecdsa_signed \
  key_ecdsa_signed.pub \
  key_ecdsa_signed-cert.pub \
  key_rsa_signed \
  key_rsa_signed-cert.pub \
  key_rsa_signed.pub \
  key_ed25519 \
  key_ed25519.pub \
  key_ed25519_encrypted \
  key_ed25519_encrypted.pub \
  key_rsa \
  key_rsa.pub \
  key_rsa_encrypted \
  key_rsa_encrypted.pub \
  key_rsa_openssh \
  key_rsa_openssh.pub \
  mansyntax.sh \
  openssh_server/Dockerfile \
  openssh_server/authorized_keys \
  openssh_server/ca_rsa \
  openssh_server/ca_rsa.pub \
  openssh_server/ca_ecdsa \
  openssh_server/ca_ecdsa.pub \
  openssh_server/ssh_host_ecdsa_key \
  openssh_server/ssh_host_ed25519_key \
  openssh_server/ssh_host_rsa_key \
  simple.c \
  sshdwrap \
  ssh2.c \
  ssh2.sh \
  sshd_fixture.sh.in \
  test_read_3des-cbc \
  test_read_aes128-cbc \
  test_read_aes128-ctr \
  test_read_aes192-cbc \
  test_read_aes192-ctr \
  test_read_aes256-cbc \
  test_read_aes256-ctr \
  test_read_hmac-md5 \
  test_read_hmac-md5-96 \
  test_read_hmac-sha1 \
  test_read_hmac-sha1-96 \
  test_read_hmac-sha2-256 \
  test_read_hmac-sha2-512 \
  test_read_rijndael-cbc
