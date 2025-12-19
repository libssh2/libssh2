---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_tell64
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_open_ex(3)
  - libssh2_sftp_tell(3)
---

# NAME

libssh2_sftp_tell64 - get the current read/write position indicator for a file

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

libssh2_uint64_t
libssh2_sftp_tell64(LIBSSH2_SFTP_HANDLE *handle);
~~~

# DESCRIPTION

*handle* - SFTP File Handle as returned by **libssh2_sftp_open_ex(3)**

Identify the current offset of the file handle's internal pointer.

# RETURN VALUE

Current offset from beginning of file in bytes.

# AVAILABILITY

Added in libssh2 1.0
