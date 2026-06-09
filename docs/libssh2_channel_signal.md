---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_signal
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_get_exit_signal(3)
  - libssh2_channel_open_ex(3)
  - libssh2_channel_signal_ex(3)
---

# NAME

libssh2_channel_signal - convenience macro for *libssh2_channel_signal_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

int libssh2_channel_signal(LIBSSH2_CHANNEL *channel, const char *signame)
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_channel_signal_ex(3)*.

# RETURN VALUE

See *libssh2_channel_signal_ex(3)*

# AVAILABILITY

Added in libssh2 1.11.0
