---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_receive_window_adjust2
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_window_read_ex(3)
---

# NAME

libssh2_channel_receive_window_adjust2 - adjust the channel window

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_receive_window_adjust2(LIBSSH2_CHANNEL * channel,
                                       unsigned long adjustment,
                                       unsigned char force,
                                       unsigned int *window);
~~~

# DESCRIPTION

Adjust the receive window for a channel by adjustment bytes. If the amount to
be adjusted is less than LIBSSH2_CHANNEL_MINADJUST and force is 0 the
adjustment amount will be queued for a later packet.

This function stores the new size of the receive window (as understood by
remote end) in the variable 'window' points to.

# RETURN VALUE

Return 0 on success and a negative value on error. If used in non-blocking
mode it will return LIBSSH2_ERROR_EAGAIN when it would otherwise block.

# ERRORS

# AVAILABILITY

Added in libssh2 1.1 since the previous API has deficiencies.
