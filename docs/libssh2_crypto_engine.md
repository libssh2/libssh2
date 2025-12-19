---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_crypto_engine
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_crypto_engine - retrieve used crypto engine

# SYNOPSIS

~~~c
#include <libssh2.h>

libssh2_crypto_engine_t
libssh2_crypto_engine(void);
~~~

# DESCRIPTION

Returns currently used crypto engine, as en enum value.

# AVAILABILITY

Added in libssh2 1.11
