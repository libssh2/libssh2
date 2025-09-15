---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_hostkey_hash
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_hostkey_hash - return a hash of the remote host's key

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *
libssh2_hostkey_hash(LIBSSH2_SESSION *session, int hash_type);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*hash_type* - One of: **LIBSSH2_HOSTKEY_HASH_MD5**,
**LIBSSH2_HOSTKEY_HASH_SHA1** or **LIBSSH2_HOSTKEY_HASH_SHA256**.

Returns the computed digest of the remote system's hostkey. The length of
the returned string is hash_type specific (e.g. 16 bytes for MD5,
20 bytes for SHA1, 32 bytes for SHA256).

# RETURN VALUE

Computed hostkey hash value, or NULL if the information is not available
(either the session has not yet been started up, or the requested hash
algorithm was not available). The hash consists of raw binary bytes, not hex
digits, so it is not directly printable.
