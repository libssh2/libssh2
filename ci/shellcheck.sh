#!/bin/sh
# Copyright (C) Viktor Szakats
#
# SPDX-License-Identifier: curl

set -eu

cd "$(dirname "$0")"/..

# shellcheck disable=SC2046
shellcheck --exclude=1091 \
  --enable=avoid-nullary-conditions,deprecate-which \
  $(grep -l -E '^#!(/usr/bin/env bash|/bin/sh|/bin/bash)' $(git ls-files))
