---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_seek64
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_seek64 - set the read/write position within a file

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

void
libssh2_sftp_seek64(LIBSSH2_SFTP_HANDLE *handle,
                    libssh2_uint64_t offset);
~~~

# DESCRIPTION

*handle* - SFTP File Handle as returned by libssh2_sftp_open_ex(3)

*offset* - Number of bytes from the beginning of file to seek to.

Move the file handle's internal pointer to an arbitrary location. libssh2
implements file pointers as a localized concept to make file access appear
more POSIX like. No packets are exchanged with the server during a seek
operation. The localized file pointer is used as a convenience offset during
read/write operations.

You MUST NOT seek during writing or reading a file with SFTP, as the internals
use outstanding packets and changing the "file position" during transit will
results in badness.

# AVAILABILITY

Added in 1.0
