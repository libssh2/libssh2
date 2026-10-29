#!/usr/bin/env bash
# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

set -eu

# This script is called by the oss-fuzz main project when compiling the fuzz
# targets. This script is regression tested by ci/ossfuzz.sh.

# Save off the current folder as the build root.
export BUILD_ROOT="$PWD"

export CPPFLAGS
CPPFLAGS+=' -DLIBSSH2_HMAC_SHA1_ENABLE'  # Workaround for hang then timeout

echo "CC: ${CC:-}"
echo "CXX: ${CXX:-}"
echo "LIB_FUZZING_ENGINE: ${LIB_FUZZING_ENGINE:-}"
echo "CFLAGS: ${CFLAGS:-}"
echo "CXXFLAGS: ${CXXFLAGS:-}"
echo "CPPFLAGS: ${CPPFLAGS:-}"
echo "OUT: ${OUT:-}"

MAKEFLAGS+=" -j$(nproc)"
export MAKEFLAGS

# Install dependencies
apt-get -y install automake libtool libssl-dev zlib1g-dev

# Compile the fuzzer.
autoreconf -fi
./configure --disable-dependency-tracking \
            --disable-shared \
            --enable-ossfuzzers \
            --disable-examples-build \
            --disable-docs \
            --enable-debug
make V=1

# Copy the fuzzers to the output directory.
cp -v tests/ossfuzz/ssh2_client_fuzzer "$OUT/"
cp -v tests/ossfuzz/ssh2_sftp_packet_fuzzer "$OUT/"
cp -v tests/ossfuzz/ssh2_knownhost_fuzzer "$OUT/"
