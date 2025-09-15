---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_handle_extended_data
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_handle_extended_data2(3)
  - libssh2_channel_read_ex(3)
---

# NAME

libssh2_channel_handle_extended_data - set extended data handling mode

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_channel_handle_extended_data(LIBSSH2_CHANNEL *channel,
                                     int ignore_mode);
~~~

# DESCRIPTION

This function is **DEPRECATED** in 1.1.0. Use the
*libssh2_channel_handle_extended_data2(3)* function instead!

*channel* - Active channel stream to change extended data handling on.

*ignore_mode* - One of the three LIBSSH2_CHANNEL_EXTENDED_DATA_* Constants.

**LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL**: Queue extended data for eventual
reading

**LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE**: Treat extended data and ordinary
data the same. Merge all substreams such that calls to
*libssh2_channel_read(3)* will pull from all substreams on a
first-in/first-out basis.

**LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE**: Discard all extended data as it
arrives.

Change how a channel deals with extended data packets. By default all extended
data is queued until read by *libssh2_channel_read_ex(3)*

# RETURN VALUE

None.
