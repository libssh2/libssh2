---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_publickey_add_ex
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_publickey_add_ex - Add a public key entry

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_publickey_add_ex(LIBSSH2_PUBLICKEY *pkey,
                         const unsigned char *name, unsigned long name_len,
                         const unsigned char *blob, unsigned long blob_len,
                         char overwrite, unsigned long num_attrs,
                         const libssh2_publickey_attribute attrs[])
~~~

# DESCRIPTION

TBD

# RETURN VALUE

Returns 0 on success, negative on failure.

# ERRORS

LIBSSH2_ERROR_BAD_USE
LIBSSH2_ERROR_ALLOC,
LIBSSH2_ERROR_EAGAIN
LIBSSH2_ERROR_SOCKET_SEND,
LIBSSH2_ERROR_SOCKET_TIMEOUT,
LIBSSH2_ERROR_PUBLICKEY_PROTOCOL,
