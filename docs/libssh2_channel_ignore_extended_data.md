---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_ignore_extended_data
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_handle_extended_data(3)
---

# NAME

libssh2_channel_ignore_extended_data - convenience macro for *libssh2_channel_handle_extended_data(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_channel_ignore_extended_data(LIBSSH2_CHANNEL *channel,
                                     int ignore_mode);
~~~

# DESCRIPTION

This function is **DEPRECATED** in 0.3.0. Use the
*libssh2_channel_handle_extended_data2(3)* function instead!

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_channel_handle_extended_data(3)*.

# RETURN VALUE

See *libssh2_channel_handle_extended_data(3)*

# ERRORS

See *libssh2_channel_handle_extended_data(3)*
