#!/bin/sh
#
# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

set -e
set -u

cd "$(dirname "$0")"

rm -rf bld-fetchcontent; cmake -B bld-fetchcontent -DTEST_INTEGRATION_MODE=FetchContent
make -C bld-fetchcontent -j3

rm -rf libssh2; ln -s ../.. libssh2
rm -rf bld-add_subdirectory; cmake -B bld-add_subdirectory -DTEST_INTEGRATION_MODE=add_subdirectory
make -C bld-add_subdirectory -j3

rm -rf bld-libssh2; cmake ../.. -B bld-libssh2
make -C bld-libssh2 -j3 DESTDIR=pkg install
rm -rf bld-find_package; cmake -B bld-find_package -DTEST_INTEGRATION_MODE=find_package -DCMAKE_PREFIX_PATH="${PWD}/bld-libssh2/pkg/usr/local/lib/cmake/libssh2"
make -C bld-find_package -j3
