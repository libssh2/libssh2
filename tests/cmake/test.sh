#!/bin/sh
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

set -eu

cd "$(dirname "$0")"

command -v ninja >/dev/null && export CMAKE_GENERATOR=Ninja  # 3.17+

mode="${1:-all}"; shift

cmake_consumer="${CMAKE_CONSUMER:-cmake}"
cmake_provider="${CMAKE_PROVIDER:-${cmake_consumer}}"

# 'modern': supports -S/-B (3.13+), --install (3.15+)
"${cmake_consumer}" --help | grep -q -- '--install' && cmake_consumer_modern=1
"${cmake_provider}" --help | grep -q -- '--install' && cmake_provider_modern=1

src='../..'

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then
  src="${PWD}/${src}"
  bld='bld-fetchcontent'
  rm -rf "${bld}"
  "${cmake_consumer}" -B "${bld}" \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${src}" \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  "${cmake_consumer}" --build "${bld}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf libssh2; ln -s "${src}" libssh2
  bld='bld-add_subdirectory'
  rm -rf "${bld}"
  "${cmake_consumer}" -B "${bld}" \
    -DTEST_INTEGRATION_MODE=add_subdirectory
  "${cmake_consumer}" --build "${bld}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  crypto="${2:-OpenSSL}"
  bldp="bld-libssh2-${crypto}"
  prefix="${PWD}/${bldp}/_pkg"
  rm -rf "${bldp}"
  "${cmake_provider}" "${src}" -B "${bldp}" -DCMAKE_INSTALL_PREFIX="${prefix}" \
    -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF \
    -DENABLE_ZLIB_COMPRESSION=ON \
    -DCRYPTO_BACKEND="${crypto}"
  "${cmake_provider}" --build "${bldp}"
  "${cmake_provider}" --install "${bldp}"
  bld='bld-find_package'
  rm -rf "${bld}"
  "${cmake_consumer}" -B "${bld}" \
    -DTEST_INTEGRATION_MODE=find_package \
    -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/libssh2"
  "${cmake_consumer}" --build "${bld}" --verbose
fi
