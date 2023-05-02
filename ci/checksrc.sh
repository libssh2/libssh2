#!/usr/bin/env bash

set -e

cd "$(dirname "$0")/.."

FILES="src/*.[ch] include/*.h example/*.c tests/*.[ch]"
WHITELIST="-Wsrc/libssh2_config.h"

# shellcheck disable=SC2086
# shellcheck disable=SC2248
perl ./ci/checksrc.pl -i4 -m79 \
  -ASNPRINTF \
  -ACOPYRIGHT \
  -AFOPENMODE \
  -ATYPEDEFSTRUCT \
  $WHITELIST $FILES
