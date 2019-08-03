#!/usr/bin/env bash

set -e

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}

. $SOURCE_DIR/ci/conf.sh

mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"

pwd
echo "Configuring…"
cmake $CMAKE_FLAGS \
    -DCRYPTO_BACKEND=$CRYPTO_BACKEND \
    -DBUILD_SHARED_LIBS=ON \
    -DENABLE_DEBUG_LOGGING=ON \
    -DENABLE_ZLIB_COMPRESSION=$ENABLE_ZLIB_COMPRESSION .. $@

echo "Building…"
cmake --build .
