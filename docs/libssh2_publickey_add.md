---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_publickey_add
Section: 3
Source: libssh2
See-also:
  - libssh2_publickey_add_ex(3)
---

# NAME

libssh2_publickey_add - convenience macro for *libssh2_publickey_add_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_publickey_add(LIBSSH2_PUBLICKEY *pkey,
                      const unsigned char *name,
                      const unsigned char *blob, unsigned long blob_len,
                      char overwrite, unsigned long num_attrs,
                      const libssh2_publickey_attribute attrs[]);
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_publickey_add_ex(3)*.

# RETURN VALUE

See *libssh2_publickey_add_ex(3)*

# ERRORS

See *libssh2_publickey_add_ex(3)*
