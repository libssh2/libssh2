---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_block_directions
Section: 3
Source: libssh2
See-also:
---

# NAME

libssh2_session_block_directions - get directions to wait for

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_session_block_directions(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

*session* - Session instance as returned by **libssh2_session_init_ex(3)**

When any of libssh2 functions return **LIBSSH2_ERROR_EAGAIN** an application
should wait for the socket to have data available for reading or
writing. Depending on the return value of
*libssh2_session_block_directions(3)* an application should wait for read,
write or both.

# RETURN VALUE

Returns the set of directions as a binary mask. Can be a combination of:

LIBSSH2_SESSION_BLOCK_INBOUND: Inbound direction blocked.

LIBSSH2_SESSION_BLOCK_OUTBOUND: Outbound direction blocked.

Application should wait for data to be available for socket prior to calling a
libssh2 function again. If **LIBSSH2_SESSION_BLOCK_INBOUND** is set select
should contain the session socket in readfds set. Correspondingly in case of
**LIBSSH2_SESSION_BLOCK_OUTBOUND** writefds set should contain the socket.

# AVAILABILITY

Added in 1.0
