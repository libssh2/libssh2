---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_exec
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_process_startup(3)
---

# NAME

libssh2_channel_exec - convenience macro for *libssh2_channel_process_startup(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_exec(LIBSSH2_CHANNEL *channel, const char *command);
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_channel_process_startup(3)*.

# RETURN VALUE

See *libssh2_channel_process_startup(3)*

# ERRORS

See *libssh2_channel_process_startup(3)*
