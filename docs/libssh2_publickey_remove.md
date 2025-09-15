---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_publickey_remove
Section: 3
Source: libssh2
See-also:
  - libssh2_publickey_remove_ex(3)
---

# NAME

libssh2_publickey_remove - convenience macro for *libssh2_publickey_remove_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_publickey_remove(LIBSSH2_PUBLICKEY *pkey,
                         const unsigned char *name, unsigned long name_len,
                         const unsigned char *blob, unsigned long blob_len);
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_publickey_remove_ex(3)*.

# RETURN VALUE

See *libssh2_publickey_remove_ex(3)*

# ERRORS

See *libssh2_publickey_remove_ex(3)*
