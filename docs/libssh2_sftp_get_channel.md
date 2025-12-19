---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_get_channel
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
---

# NAME

libssh2_sftp_get_channel - return the channel of sftp

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

LIBSSH2_CHANNEL *
libssh2_sftp_get_channel(LIBSSH2_SFTP *sftp);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

Return the channel of the given sftp handle.

# RETURN VALUE

The channel of the SFTP instance or NULL if something was wrong.

# AVAILABILITY

Added in 1.4.0
