#!/usr/bin/env bash
# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

set -e

cd "$(dirname "$0")/.."

perl ./ci/checksrc.pl -i4 -m79 \
  -Wsrc/libssh2_config.h \
  src/*.[ch] include/*.h example/*.c tests/*.[ch]
