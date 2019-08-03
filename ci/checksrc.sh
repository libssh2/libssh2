#!/usr/bin/env bash

set -e

FILES="src/*.[ch] include/*.h example/*.c tests/*.[ch] tests/testcases/*/*.c"
WHITELIST="-Wsrc/libssh2_config.h \
    -Wtests/clar.c \
    -Wtests/clar.h \
"

perl ./ci/checksrc.pl -i4 -m79 -ASIZEOFNOPAREN -ASNPRINTF -ACOPYRIGHT -AFOPENMODE $WHITELIST $FILES
