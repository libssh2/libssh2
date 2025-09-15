---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_flag
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_session_flag - TODO

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_flag(LIBSSH2_SESSION *session, int flag, int value);
~~~

# DESCRIPTION

Set options for the created session. *flag* is the option to set, while
*value* is typically set to 1 or 0 to enable or disable the option.

# FLAGS

## LIBSSH2_FLAG_SIGPIPE

If set, libssh2 will not attempt to block SIGPIPEs but will let them trigger
from the underlying socket layer.

## LIBSSH2_FLAG_COMPRESS

If set - before the connection negotiation is performed - libssh2 will try to
negotiate compression enabling for this connection. By default libssh2 will
not attempt to use compression.

# RETURN VALUE

Returns regular libssh2 error code.

# AVAILABILITY

This function has existed since the age of dawn. LIBSSH2_FLAG_COMPRESS was
added in version 1.2.8.
