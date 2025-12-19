---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_publickey
Section: 3
Source: libssh2
See-also:
  - libssh2_userauth_publickey_fromfile_ex(3)
---

# NAME

libssh2_userauth_publickey - authenticate using a callback function

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_publickey(LIBSSH2_SESSION *session,
                           const char *user,
                           const unsigned char *pubkeydata,
                           size_t pubkeydata_len,
                           sign_callback,
                           void **abstract);
~~~

# DESCRIPTION

Authenticate with the *sign_callback* callback that matches the prototype
below

# CALLBACK

~~~c
int name(LIBSSH2_SESSION *session, unsigned char **sig, size_t *sig_len,
         const unsigned char *data, size_t data_len, void **abstract);
~~~

This function gets called...

# RETURN VALUE

Return 0 on success or negative on failure.
