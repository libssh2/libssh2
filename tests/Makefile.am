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
  test_agent_forward_succeeds \
  test_hostkey \
  test_hostkey_hash \
  test_keyboard_interactive_auth_fails_with_wrong_response \
  test_keyboard_interactive_auth_info_request \
  test_keyboard_interactive_auth_succeeds_with_correct_response \
  test_password_auth_fails_with_wrong_password \
  test_password_auth_fails_with_wrong_username \
  test_password_auth_succeeds_with_correct_credentials \
  test_public_key_auth_fails_with_wrong_key \
  test_public_key_auth_succeeds_with_correct_dsa_key \
  test_public_key_auth_succeeds_with_correct_ecdsa_key \
  test_public_key_auth_succeeds_with_correct_ed25519_key \
  test_public_key_auth_succeeds_with_correct_ed25519_key_from_mem \
  test_public_key_auth_succeeds_with_correct_encrypted_ed25519_key \
  test_public_key_auth_succeeds_with_correct_encrypted_rsa_key \
  test_public_key_auth_succeeds_with_correct_rsa_key \
  test_public_key_auth_succeeds_with_correct_rsa_openssh_key \
  test_public_key_auth_succeeds_with_correct_signed_ecdsa_key \
  test_public_key_auth_succeeds_with_correct_signed_rsa_key \
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
test_keyboard_interactive_auth_info_request_LDFLAGS = -static

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
  signed_key_ecdsa \
  signed_key_ecdsa.pub \
  signed_key_ecdsa-cert.pub \
  signed_key_rsa \
  signed_key_rsa-cert.pub \
  signed_key_rsa.pub \
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
