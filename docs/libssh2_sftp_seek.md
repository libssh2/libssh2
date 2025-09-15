---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_seek
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_open_ex(3)
  - libssh2_sftp_seek64(3)
---

# NAME

libssh2_sftp_seek - set the read/write position indicator within a file

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

void
libssh2_sftp_seek(LIBSSH2_SFTP_HANDLE *handle,
                  size_t offset);
~~~

# DESCRIPTION

Deprecated function. Use *libssh2_sftp_seek64(3)* instead!

*handle* - SFTP File Handle as returned by libssh2_sftp_open_ex(3)

*offset* - Number of bytes from the beginning of file to seek to.

Move the file handle's internal pointer to an arbitrary location.
Note that libssh2 implements file pointers as a localized concept to make
file access appear more POSIX like. No packets are exchanged with the server
during a seek operation. The localized file pointer is used as a convenience
offset during read/write operations.
