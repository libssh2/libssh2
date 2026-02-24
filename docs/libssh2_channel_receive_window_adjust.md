---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_receive_window_adjust
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_window_read_ex(3)
---

# NAME

libssh2_channel_receive_window_adjust - adjust the channel window

# SYNOPSIS

~~~c
#include <libssh2.h>

unsigned long
libssh2_channel_receive_window_adjust(LIBSSH2_CHANNEL * channel,
                                      unsigned long adjustment,
                                      unsigned char force);
~~~

# DESCRIPTION

This function is **DEPRECATED** in 1.1.0. Use the
*libssh2_channel_receive_window_adjust2(3)* function instead!

Adjust the receive window for a channel by adjustment bytes. If the amount to
be adjusted is less than LIBSSH2_CHANNEL_MINADJUST and force is 0 the
adjustment amount will be queued for a later packet.

# RETURN VALUE

Returns the new size of the receive window (as understood by remote end). Note
that the window value sent over the wire is strictly 32bit, but this API is
made to return a 'long' which may not be 32 bit on all platforms.

# ERRORS

In 1.0 and earlier, this function returns LIBSSH2_ERROR_EAGAIN for
non-blocking channels where it would otherwise block. However, that is a
negative number and this function only returns an unsigned value and this then
leads to a very strange value being returned.
