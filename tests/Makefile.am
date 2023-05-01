SUBDIRS = ossfuzz

AM_CPPFLAGS = -I$(top_builddir)/src -I$(top_srcdir)/src -I$(top_srcdir)/include

# Get DOCKER_TESTS, STANDALONE_TESTS, SSHD_TESTS, librunner_la_SOURCES defines
include Makefile.inc

# FIXME: Exported by autotools with the same value by default anyway?
TESTS_ENVIRONMENT = srcdir=$(top_srcdir)/tests builddir=$(top_builddir)/tests

# Tests to run
TESTS = mansyntax.sh

if RUN_DOCKER_TESTS
TESTS += $(DOCKER_TESTS)
endif

TESTS += $(STANDALONE_TESTS)

# TAP tests
TEST_EXTENSIONS = .test
# 'TEST' in 'TEST_LOG_DRIVER' is the test extension in uppercase.
TEST_LOG_DRIVER = $(SHELL) $(top_srcdir)/tap-driver.sh

TESTS_ENVIRONMENT += EXEEXT=$(EXEEXT)
if RUN_SSHD_TESTS
if SSHD
TESTS += test_sshd.test
TESTS_ENVIRONMENT += SSHD="$(SSHD)"
endif
endif
if RUN_DOCKER_TESTS
TESTS += test_read_algos.test
endif

# Tests to build
check_PROGRAMS = $(DOCKER_TESTS) $(STANDALONE_TESTS) $(SSHD_TESTS)

# Internal library used by tests
LDADD = librunner.la
check_LTLIBRARIES = librunner.la

# These programs use internal libssh2 functions so they need to be statically
# linked against libssh2
test_auth_keyboard_info_request_LDFLAGS = -static
test_hostkey_LDFLAGS = -static
test_simple_LDFLAGS = -static

# This must be last in the list so it resolves symbols in previous libraries
LDADD += ../src/libssh2.la
