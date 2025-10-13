#!/bin/sh
# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

set -eu

cd "$(dirname "$0")"/..

# shellcheck disable=SC2046
codespell --skip='docs/AUTHORS' \
  --ignore-words='ci/codespell-ignore.words' \
  $(git ls-files)
