---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_window_read_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_receive_window_adjust(3)
  - libssh2_channel_window_write_ex(3)
---

# NAME

libssh2_channel_window_read_ex - Check the status of the read window

# SYNOPSIS

~~~c
#include <libssh2.h>

unsigned long
libssh2_channel_window_read_ex(LIBSSH2_CHANNEL *channel,
                               unsigned long *read_avail,
                               unsigned long *window_size_initial)
~~~

# DESCRIPTION

Check the status of the read window. Returns the number of bytes which the
remote end may send without overflowing the window limit read_avail (if
passed) will be populated with the number of bytes actually available to be
read window_size_initial (if passed) will be populated with the
window_size_initial as defined by the channel_open request

# RETURN VALUE

The number of bytes which the remote end may send without overflowing the
window limit

# ERRORS
