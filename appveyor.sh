#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: BSD-3-Clause

# https://www.appveyor.com/docs/windows-images-software/

# shellcheck disable=SC3040,SC2039
set -eux; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Install custom cmake version
if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" != 'Visual Studio 2022' ]; then
  if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" = 'Visual Studio 2026' ]; then
    CMAKE_VERSION=${CMAKE_NEW_VERSION}
    CMAKE_SHA256=${CMAKE_NEW_SHA256}
  else
    CMAKE_VERSION=${CMAKE_OLD_VERSION}
    CMAKE_SHA256=${CMAKE_OLD_SHA256}
  fi
  cmake_ver="$(printf '%02d%02d' \
    "$(echo "${CMAKE_VERSION}" | cut -f1 -d.)" \
    "$(echo "${CMAKE_VERSION}" | cut -f2 -d.)")"
  if [ "${cmake_ver}" -ge '0320' ]; then
    fn="cmake-${CMAKE_VERSION}-windows-x86_64"
  else
    fn="cmake-${CMAKE_VERSION}-win64-x64"
  fi
  curl --disable --fail --silent --show-error --connect-timeout 15 --max-time 60 --retry 3 --retry-connrefused \
    --location --proto-redir =https "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${fn}.zip" --output pkg.bin
  sha256sum pkg.bin && sha256sum pkg.bin | grep -qwF -- "${CMAKE_SHA256}" && 7z x -y pkg.bin >/dev/null && rm -f pkg.bin
  mv "${fn}" /c/my-cmake
fi

echo "CMake job options: ${CMAKE_GENERATE:-}"
options=''
if [[ "${TESTS:-}" != *'skipall'* ]]; then
  options+=' -DRUN_SSHD_TESTS=OFF'
else
  options+=' -DBUILD_TESTING=OFF'
fi
# FIXME: First sshd test sometimes timeouts, subsequent ones almost always fail:
#        'libssh2_session_handshake failed (-43): Failed getting banner'
# shellcheck disable=SC2086
cmake -B _bld \
  -DCMAKE_UNITY_BUILD=ON -DENABLE_WERROR=ON \
  -DCMAKE_VS_GLOBALS=TrackFileAccess=false \
  -DLIBSSH2_BUILD_DOCS=OFF \
  ${CMAKE_GENERATE:-} \
  ${options}
echo 'libssh2_config.h'; grep -F '#define' _bld/src/libssh2_config.h | sort || true
time cmake --build _bld --config "${CMAKE_CONFIGURATION}" --parallel 2

# build examples

if [[ "${APPVEYOR_JOB_NAME}" = *'examples'* ]]; then
  time cmake --build _bld --config "${CMAKE_CONFIGURATION}" --parallel 2 --target libssh2-examples-build
fi

# Install docker-cli for tests

if [[ "${TESTS:-}" != *'skipall'* && "${TESTS:-}" != *'skiprun'* ]]; then
(
  cd /c && mkdir my-docker && cd my-docker
  curl --disable --fail --silent --show-error --connect-timeout 15 --max-time 120 --retry 3 --retry-connrefused \
    "https://download.docker.com/win/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.zip" --output pkg.bin
  sha256sum pkg.bin && sha256sum pkg.bin | grep -qwF -- "${DOCKER_CLI_SHA256}" && 7z x -y pkg.bin >/dev/null && rm -f pkg.bin && ls -l && docker --version
)
fi

# run tests

if [[ "${TESTS:-}" != *'skipall'* && "${TESTS:-}" != *'skiprun'* ]]; then
  if [[ "${CMAKE_GENERATE:-}" = *'WinCNG'* ]]; then
    export FIXTURE_TRACE_ALL_CONNECT=1
  fi
  export OPENSSH_SERVER_IMAGE; OPENSSH_SERVER_IMAGE="ghcr.io/libssh2/ci_tests_openssh_server:$(git rev-parse --short=20 HEAD:tests/openssh_server)"
  # Connection to test server has been failing consistently since 2024-08-29
  cd _bld; ctest -VV -C "${CMAKE_CONFIGURATION}" --output-on-failure --timeout 900
fi

# disk space used
du -sh .; echo; du -sh -t 250KB ./*; echo; du -h -t 250KB _bld
