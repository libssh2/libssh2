#!/usr/bin/env bash
# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

set -eu

cd "$(dirname "$0")"/..

git ls-files "*.[ch]" "*.cc" | xargs -n1 \
ci/checksrc.pl -i4 -m79 -AFOPENMODE -ASNPRINTF -ATYPEDEFSTRUCT
