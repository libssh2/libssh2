---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_window_write_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_receive_window_adjust(3)
  - libssh2_channel_window_read_ex(3)
---

# NAME

libssh2_channel_window_write_ex - Check the status of the write window

# SYNOPSIS

~~~c
#include <libssh2.h>

unsigned long
libssh2_channel_window_write_ex(LIBSSH2_CHANNEL *channel,
                                unsigned long *window_size_initial)
~~~

# DESCRIPTION

Check the status of the write window Returns the number of bytes which may be
safely written on the channel without blocking. 'window_size_initial' (if
passed) will be populated with the size of the initial window as defined by
the channel_open request

# RETURN VALUE

Number of bytes which may be safely written on the channel without blocking.

# ERRORS
