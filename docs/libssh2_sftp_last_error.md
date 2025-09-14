---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_last_error
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
---

# NAME

libssh2_sftp_last_error - return the last SFTP-specific error code

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

unsigned long
libssh2_sftp_last_error(LIBSSH2_SFTP *sftp);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

Returns the last error code produced by the SFTP layer. Note that this only
returns a sensible error code if libssh2 returned LIBSSH2_ERROR_SFTP_PROTOCOL
in a previous call. Using **libssh2_sftp_last_error(3)** without a
preceding SFTP protocol error, it will return an unspecified value.

# RETURN VALUE

Current error code state of the SFTP instance.
