SUBDIRS = ossfuzz

AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src -I$(top_srcdir)/include

# Keep this list sorted
#
# NOTE: test_auth_keyboard_info_request does not use the network, but when
#       run as Windows standalone test, it intermittently fails on GHA with:
#         `Terminate batch job (Y/N)?`
DOCKER_TESTS = \
  test_aa_warmup \
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

STANDALONE_TESTS = \
  test_simple

SSHD_TESTS = \
  test_ssh2 \
  test_auth_pubkey_ok_ed25519

# FIXME: Exported by autotools with the same value by default anyway?
TESTS_ENVIRONMENT = srcdir=$(top_srcdir)/tests builddir=$(top_builddir)/tests

# Tests to run
TESTS = mansyntax.sh

if ! HOST_WINDOWS
TESTS += $(DOCKER_TESTS)
endif

TESTS += $(STANDALONE_TESTS)

# TAP tests
TEST_EXTENSIONS = .test
# 'TEST' in 'TEST_LOG_DRIVER' is the test extension in uppercase.
TEST_LOG_DRIVER = $(SHELL) $(top_srcdir)/tap-driver.sh

TESTS_ENVIRONMENT += EXEEXT=$(EXEEXT)
if SSHD
TESTS += test_sshd.test
TESTS_ENVIRONMENT += SSHD="$(SSHD)"
endif
TESTS += test_read_algos.test

# Tests to build
check_PROGRAMS = $(DOCKER_TESTS) $(STANDALONE_TESTS) $(SSHD_TESTS)

# Internal library used by tests
librunner_la_SOURCES = \
  runner.c runner.h \
  session_fixture.c session_fixture.h \
  openssh_fixture.c openssh_fixture.h
LDADD = librunner.la
check_LTLIBRARIES = librunner.la

# These programs use internal libssh2 functions so they need to be statically
# linked against libssh2
test_auth_keyboard_info_request_LDFLAGS = -static
test_hostkey_LDFLAGS = -static
test_simple_LDFLAGS = -static

# This must be last in the list so it resolves symbols in previous libraries
LDADD += ../src/libssh2.la

EXTRA_DIST = \
  CMakeLists.txt \
  key_dsa \
  key_dsa.pub \
  key_dsa_wrong \
  key_dsa_wrong.pub \
  key_ecdsa \
  key_ecdsa.pub \
  key_ecdsa_signed \
  key_ecdsa_signed-cert.pub \
  key_ecdsa_signed.pub \
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
  key_rsa_signed \
  key_rsa_signed-cert.pub \
  key_rsa_signed.pub \
  mansyntax.sh \
  openssh_server/Dockerfile \
  openssh_server/authorized_keys \
  openssh_server/ca_ecdsa \
  openssh_server/ca_ecdsa.pub \
  openssh_server/ca_rsa \
  openssh_server/ca_rsa.pub \
  openssh_server/ca_user_keys.pub \
  openssh_server/ssh_host_dsa_key \
  openssh_server/ssh_host_ecdsa_key \
  openssh_server/ssh_host_ed25519_key \
  openssh_server/ssh_host_rsa_key \
  openssh_server/sshd_config \
  test_read_algos.test \
  test_read_algos.txt \
  test_sshd.test \
  sshd_fixture.sh
