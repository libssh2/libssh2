#!/bin/sh
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

set -e
set -u

cd "$(dirname "$0")"

export CMAKE_GENERATOR=Ninja

rm -rf bld-fetchcontent; cmake -B bld-fetchcontent \
  -DTEST_INTEGRATION_MODE=FetchContent \
  -DFROM_GIT_REPO="${PWD}/../.." \
  -DFROM_GIT_TAG="$(git rev-parse HEAD)"
cmake --build bld-fetchcontent

rm -rf libssh2; ln -s ../.. libssh2
rm -rf bld-add_subdirectory; cmake -B bld-add_subdirectory \
  -DTEST_INTEGRATION_MODE=add_subdirectory
cmake --build bld-add_subdirectory

rm -rf bld-libssh2; cmake ../.. -B bld-libssh2
cmake --build bld-libssh2
cmake --install bld-libssh2 --prefix bld-libssh2/_pkg
rm -rf bld-find_package; cmake -B bld-find_package \
  -DTEST_INTEGRATION_MODE=find_package \
  -DCMAKE_PREFIX_PATH="${PWD}/bld-libssh2/_pkg/lib/cmake/libssh2"
cmake --build bld-find_package
