#!/usr/bin/env bash

set -e

perl ./ci/checksrc.pl -i4 -m79 -ASIZEOFNOPAREN -ASNPRINTF -ACOPYRIGHT -AFOPENMODE -Wsrc/libssh2_config.h src/*.[ch] include/*.h example/*.c
