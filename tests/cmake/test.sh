#!/bin/sh
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

set -eu

cd "$(dirname "$0")"

mode="${1:-all}"

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then
  rm -rf bld-fetchcontent
  cmake -B bld-fetchcontent \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${PWD}/../.." \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  cmake --build bld-fetchcontent
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf libssh2; ln -s ../.. libssh2
  rm -rf bld-add_subdirectory
  cmake -B bld-add_subdirectory \
    -DTEST_INTEGRATION_MODE=add_subdirectory
  cmake --build bld-add_subdirectory
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  crypto="${2:-OpenSSL}"
  bld="bld-libssh2-${crypto}"
  rm -rf "${bld}"
  cmake ../.. -B "${bld}" -DCMAKE_INSTALL_PREFIX="${PWD}/${bld}/_pkg" \
    -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
    -DENABLE_ZLIB_COMPRESSION=ON \
    -DCRYPTO_BACKEND="${crypto}"
  cmake --build "${bld}"
  cmake --install "${bld}"
  rm -rf bld-find_package
  cmake -B bld-find_package \
    -DTEST_INTEGRATION_MODE=find_package \
    -DCMAKE_PREFIX_PATH="${PWD}/${bld}/_pkg/lib/cmake/libssh2"
  cmake --build bld-find_package --verbose
fi
