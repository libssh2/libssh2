#!/usr/bin/env bash
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: BSD-3-Clause

# https://www.appveyor.com/docs/windows-images-software/

# shellcheck disable=SC3040,SC2039
set -eux; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Install custom cmake version
if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" != 'Visual Studio 2022' ]; then
  cmake_ver="$(printf '%02d%02d' \
    "$(echo "${CMAKE_VERSION}" | cut -f1 -d.)" \
    "$(echo "${CMAKE_VERSION}" | cut -f2 -d.)")"
  if [ "${cmake_ver}" -ge '0320' ]; then
    fn="cmake-${CMAKE_VERSION}-windows-x86_64"
  else
    fn="cmake-${CMAKE_VERSION}-win64-x64"
  fi
  curl --disable --fail --silent --show-error --connect-timeout 15 --max-time 60 --retry 3 --retry-connrefused \
    --location "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${fn}.zip" --output pkg.bin
  sha256sum pkg.bin && sha256sum pkg.bin | grep -qwF -- "${CMAKE_SHA256}" && 7z x -y pkg.bin >/dev/null && rm -f pkg.bin
  mv "${fn}" /c/my-cmake
fi

echo "CMake job options: ${CMAKE_GENERATE:-}"
# FIXME: First sshd test sometimes timeouts, subsequent ones almost always fail:
#        'libssh2_session_handshake failed (-43): Failed getting banner'
# shellcheck disable=SC2086
cmake -B _builds \
  -DCMAKE_UNITY_BUILD=ON -DENABLE_WERROR=ON \
  -DCMAKE_VS_GLOBALS=TrackFileAccess=false \
  -DRUN_SSHD_TESTS=OFF \
  ${CMAKE_GENERATE:-}
cmake --build _builds --config "${CMAKE_CONFIGURATION}" --parallel 2
