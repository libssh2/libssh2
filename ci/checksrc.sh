#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

perl ./ci/checksrc.pl -i4 -m79 \
  -Wsrc/libssh2_config.h \
  src/*.[ch] include/*.h example/*.c tests/*.[ch]
