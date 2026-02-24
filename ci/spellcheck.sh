#!/bin/sh
# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

set -eu

cd "$(dirname "$0")"/..

git ls-files -z | xargs -0 -r \
codespell \
  --skip 'docs/AUTHORS' \
  --ignore-words 'ci/codespell-ignore.words' \
  --
