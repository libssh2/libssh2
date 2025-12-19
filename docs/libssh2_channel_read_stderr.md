---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_read_stderr
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_read_ex(3)
---

# NAME

libssh2_channel_read_stderr - convenience macro for *libssh2_channel_read_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

ssize_t
libssh2_channel_read_stderr(LIBSSH2_CHANNEL *channel,
                            char *buf, size_t buflen);
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_channel_read_ex(3)*.

# RETURN VALUE

See *libssh2_channel_read_ex(3)*

# ERRORS

See *libssh2_channel_read_ex(3)*
