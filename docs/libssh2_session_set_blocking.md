---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_session_set_blocking
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_session_set_blocking - set or clear blocking mode on session

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_session_set_blocking(LIBSSH2_SESSION *session, int blocking);
~~~

# DESCRIPTION

*session* - session instance as returned by libssh2_session_init_ex(3)

*blocking* - Set to a non-zero value to make the channel block, or zero to
make it non-blocking.

Set or clear blocking mode on the selected on the session. This will
instantly affect any channels associated with this session. If a read is
performed on a session with no data currently available, a blocking session
will wait for data to arrive and return what it receives. A non-blocking
session will return immediately with an empty buffer. If a write is performed
on a session with no room for more data, a blocking session will wait for
room. A non-blocking session will return immediately without writing
anything.

# RETURN VALUE

None
