---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_banner_get
Section: 3
Source: libssh2
See-also:
  - libssh2_session_banner_set(3)
  - libssh2_session_free(3)
  - libssh2_session_handshake(3)
---

# NAME

libssh2_session_banner_get - get the remote banner

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *
libssh2_session_banner_get(oLIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Once the session has been setup and *libssh2_session_handshake(3)* has
completed successfully, this function can be used to get the server id from
the banner each server presents.

# RETURN VALUE

A pointer to a string or NULL if something failed. The data pointed to will be
allocated and associated to the session handle and will be freed by libssh2
when *libssh2_session_free(3)* is used.

# AVAILABILITY

Added in 1.4.0
