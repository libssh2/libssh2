---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_hostkey
Section: 3
Source: libssh2
See-also:
  - libssh2_knownhost_add(3)
  - libssh2_knownhost_check(3)
---

# NAME

libssh2_session_hostkey - get the remote key

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *
libssh2_session_hostkey(LIBSSH2_SESSION *session,
                        size_t *len, int *type);
~~~

# DESCRIPTION

Returns a pointer to the current host key, the value *len* points to will
get the length of the key.

The value *type* points to the type of hostkey which is one of:
LIBSSH2_HOSTKEY_TYPE_RSA, LIBSSH2_HOSTKEY_TYPE_DSS (deprecated), or
LIBSSH2_HOSTKEY_TYPE_UNKNOWN.

# RETURN VALUE

A pointer, or NULL if something went wrong.
