# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

AM_CPPFLAGS = -I$(top_builddir)/include
AM_CPPFLAGS += -DLIBSSH2_TESTS
# In-tree fuzzers may exercise internal APIs (declared under src/).
AM_CPPFLAGS += -I$(top_srcdir)/src

LDADD = $(top_builddir)/src/libssh2.la

if USE_OSSFUZZ_FLAG
FUZZ_FLAG = $(LIB_FUZZING_ENGINE)
else
if USE_OSSFUZZ_STATIC
LDADD += $(LIB_FUZZING_ENGINE)
FUZZ_FLAG =
else
LDADD += libstandaloneengine.a
FUZZ_FLAG =
endif
endif

noinst_PROGRAMS =
noinst_LIBRARIES =

if USE_OSSFUZZERS
noinst_PROGRAMS += \
  ssh2_client_fuzzer \
  ssh2_sftp_client_fuzzer \
  ssh2_agent_fuzzer \
  ssh2_knownhost_fuzzer \
  ssh2_pem_key_fuzzer

noinst_LIBRARIES += \
  libstandaloneengine.a
endif

ssh2_client_fuzzer_SOURCES = ssh2_client_fuzzer.cc testinput.h
ssh2_client_fuzzer_CXXFLAGS = $(AM_CXXFLAGS) $(FUZZ_FLAG)
ssh2_client_fuzzer_LDFLAGS = $(AM_LDFLAGS) -static

ssh2_sftp_client_fuzzer_SOURCES = ssh2_sftp_client_fuzzer.cc testinput.h
ssh2_sftp_client_fuzzer_CXXFLAGS = $(AM_CXXFLAGS) $(FUZZ_FLAG)
ssh2_sftp_client_fuzzer_LDFLAGS = $(AM_LDFLAGS) -static
ssh2_agent_fuzzer_SOURCES = ssh2_agent_fuzzer.cc testinput.h
ssh2_agent_fuzzer_CXXFLAGS = $(AM_CXXFLAGS) $(FUZZ_FLAG)
ssh2_agent_fuzzer_LDFLAGS = $(AM_LDFLAGS) -static
ssh2_knownhost_fuzzer_SOURCES = ssh2_knownhost_fuzzer.cc testinput.h
ssh2_knownhost_fuzzer_CXXFLAGS = $(AM_CXXFLAGS) $(FUZZ_FLAG)
ssh2_knownhost_fuzzer_LDFLAGS = $(AM_LDFLAGS) -static

libstandaloneengine_a_SOURCES = standaloneengine.cc
libstandaloneengine_a_CXXFLAGS = $(AM_CXXFLAGS)

ssh2_pem_key_fuzzer_SOURCES = ssh2_pem_key_fuzzer.cc testinput.h
ssh2_pem_key_fuzzer_CXXFLAGS = $(AM_CXXFLAGS) $(FUZZ_FLAG)
ssh2_pem_key_fuzzer_LDFLAGS = $(AM_LDFLAGS) -static

EXTRA_DIST = .checksrc CMakeLists.txt ossfuzz.sh \
  ssh2_agent_fuzzer.cc ssh2_agent_fuzzer.dict \
  ssh2_knownhost_fuzzer.cc ssh2_knownhost_fuzzer.dict \
  ssh2_pem_key_fuzzer.cc ssh2_pem_key_fuzzer.dict \
  ssh2_sftp_client_fuzzer.cc ssh2_sftp_client_fuzzer.dict \
  ssh2_agent_fuzzer_seed_corpus/* \
  ssh2_knownhost_fuzzer_seed_corpus/* \
  ssh2_pem_key_fuzzer_seed_corpus/* \
  ssh2_sftp_client_fuzzer_seed_corpus/*
