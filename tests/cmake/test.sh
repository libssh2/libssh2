#!/bin/sh -x
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

# shellcheck disable=SC2086

set -eu

cd "$(dirname "$0")"

mode="${1:-all}"; shift

cmake_consumer="${TEST_CMAKE_CONSUMER:-cmake}"
cmake_provider="${TEST_CMAKE_PROVIDER:-${cmake_consumer}}"

gen="${TEST_CMAKE_GENERATOR:-Ninja}"

cmake_opts='-DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DENABLE_ZLIB_COMPRESSION=ON'

src='../..'

runresults() {
  set +x
  for bin in "$1"/test-consumer*; do
    file "${bin}" || true
    ${TEST_CMAKE_EXE_RUNNER:-} "${bin}" || true
  done
  set -x
}

if [ "${mode}" = 'all' ] || [ "${mode}" = 'ExternalProject' ]; then
  (cd "${src}"; git archive --format=tar HEAD) | gzip > source.tar.gz
  src="${PWD}/source.tar.gz"
  sha="$(openssl dgst -sha256 "${src}" | grep -a -i -o -E '[0-9a-f]{64}$')"
  bldc='bld-externalproject'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${TEST_CMAKE_FLAGS:-} -DLIBSSH2_TEST_OPTS="${cmake_opts} -DCMAKE_UNITY_BUILD=ON $*" \
    -DTEST_INTEGRATION_MODE=ExternalProject \
    -DFROM_ARCHIVE="${src}" -DFROM_HASH="${sha}"
  "${cmake_consumer}" --build "${bldc}" --verbose
  runresults "${bldc}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'FetchContent' ]; then
  src="${PWD}/${src}"
  bldc='bld-fetchcontent'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${cmake_opts} -DCMAKE_UNITY_BUILD=ON ${TEST_CMAKE_FLAGS:-} "$@" \
    -DTEST_INTEGRATION_MODE=FetchContent \
    -DFROM_GIT_REPO="${src}" \
    -DFROM_GIT_TAG="$(git rev-parse HEAD)"
  "${cmake_consumer}" --build "${bldc}" --verbose
  PATH="${bldc}/_deps/libssh2-build/lib:${PATH}"
  runresults "${bldc}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'add_subdirectory' ]; then
  rm -rf libssh2
  if ! ln -s "${src}" libssh2; then
    rm -rf libssh2; mkdir libssh2; (cd "${src}"; git archive --format=tar HEAD) | tar -x --directory=libssh2  # for MSYS2/Cygwin
  fi
  bldc='bld-add_subdirectory'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${cmake_opts} -DCMAKE_UNITY_BUILD=ON ${TEST_CMAKE_FLAGS:-} "$@" \
    -DTEST_INTEGRATION_MODE=add_subdirectory
  "${cmake_consumer}" --build "${bldc}" --verbose
  PATH="${bldc}/libssh2/src:${PATH}"
  runresults "${bldc}"
fi

if [ "${mode}" = 'all' ] || [ "${mode}" = 'find_package' ]; then
  src="${PWD}/${src}"
  bldp='bld-libssh2'
  prefix="${PWD}/${bldp}/_pkg"
  rm -rf "${bldp}"
  "${cmake_provider}" -B "${bldp}" -S "${src}" -G "${gen}" ${cmake_opts} -DCMAKE_UNITY_BUILD=ON ${TEST_CMAKE_FLAGS:-} "$@" \
    -DCMAKE_INSTALL_PREFIX="${prefix}"
  "${cmake_provider}" --build "${bldp}" --verbose
  "${cmake_provider}" --install "${bldp}"
  bldc='bld-find_package'
  rm -rf "${bldc}"
  "${cmake_consumer}" -B "${bldc}" -G "${gen}" ${TEST_CMAKE_FLAGS:-} \
    -DTEST_INTEGRATION_MODE=find_package \
    -DCMAKE_PREFIX_PATH="${prefix}/lib/cmake/libssh2"
  "${cmake_consumer}" --build "${bldc}" --verbose
  PATH="${prefix}/bin:${PATH}"
  runresults "${bldc}"
fi
