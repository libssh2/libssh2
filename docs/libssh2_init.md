---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_init
Section: 3
Source: libssh2
See-also:
  - libssh2_exit(3)
---

# NAME

libssh2_init - global library initialization

# SYNOPSIS

~~~c
#include <libssh2.h>

#define LIBSSH2_INIT_NO_CRYPTO 0x0001

int
libssh2_init(int flags);
~~~

# DESCRIPTION

Initialize the libssh2 functions. This typically initialize the
crypto library. It uses a global state, and is not thread safe -- you
must make sure this function is not called concurrently.

# RETURN VALUE

Returns 0 if succeeded, or a negative value for error.

# AVAILABILITY

Added in libssh2 1.2.5
