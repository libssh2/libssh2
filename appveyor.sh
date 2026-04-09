#!/usr/bin/env bash
# Copyright (C) Ruslan Baratov
# Copyright (C) Alexander Lamaison
# Copyright (C) Marc Hoersken
# Copyright (C) Viktor Szakats
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# SPDX-License-Identifier: BSD-3-Clause

# https://www.appveyor.com/docs/windows-images-software/

# shellcheck disable=SC3040,SC2039
set -eux; [ -n "${BASH:-}${ZSH_NAME:-}" ] && set -o pipefail

# Install custom cmake version
if [ "${APPVEYOR_BUILD_WORKER_IMAGE}" != 'Visual Studio 2022' ]; then

  CMAKE_VERSION=3.18.4
  CMAKE_SHA256=a932bc0c8ee79f1003204466c525b38a840424d4ae29f9e5fb88959116f2407d

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
