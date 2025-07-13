#!/bin/sh
# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

set -eu

# Written by Mikhail Gusarov
#
# Run syntax checks for all manpages in the documentation tree.
#
# Requirement on macOS: brew install man-db
#

command -v gman >/dev/null 2>&1 && man() { gman "$@"; }

dstdir="${builddir:-$PWD}"
mandir="$(dirname "$0")/../docs"

ec=0

#
# Only test if suitable man is available
#
if command -v grep >/dev/null 2>&1 && \
   man --help 2>/dev/null | grep -q warnings; then

  trap 'rm -f "$dstdir/man3"' EXIT HUP INT TERM

  # Tell 'man' to not pipe the output through 'col'.
  # 'col' is missing from Cygwin since util-linux 2.40.2-1 (2024-12-24).
  export MAN_KEEP_FORMATTING=1

  ln -sf "$mandir" "$dstdir/man3"

  for manpage in "$mandir"/libssh2_*.*; do
    echo "$manpage"
    warnings=$(LANG=en_US.UTF-8 MANWIDTH=80 man -M "$dstdir" --warnings \
      -E UTF-8 -l "$manpage" 2>&1 >/dev/null)
    if [ -n "$warnings" ]; then
      echo "$warnings"
      ec=1
    fi
  done
else
  echo 'mansyntax: Required tool not found, skipping tests.'
fi

exit "$ec"
