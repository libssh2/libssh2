---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_stat_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
  - libssh2_sftp_lstat(3)
  - libssh2_sftp_stat(3)
---

# NAME

libssh2_sftp_stat_ex - get status about an SFTP file

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_stat_ex(LIBSSH2_SFTP *sftp, const char *path,
                     unsigned int path_len, int stat_type,
                     LIBSSH2_SFTP_ATTRIBUTES *attrs);
~~~

# DESCRIPTION

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

*path* - Remote filesystem object to stat/lstat/setstat.

*path_len* - Length of the name of the remote filesystem object
to stat/lstat/setstat.

*stat_type* - One of the three constants specifying the type of
stat operation to perform:

**LIBSSH2_SFTP_STAT**: performs stat(2) operation

**LIBSSH2_SFTP_LSTAT**: performs lstat(2) operation

**LIBSSH2_SFTP_SETSTAT**: performs operation to set stat info on file

*attrs* - Pointer to a **LIBSSH2_SFTP_ATTRIBUTES** structure to set file
metadata from or into depending on the value of stat_type.

Get or Set statbuf type data on a remote filesystem object. When getting
statbuf data, libssh2_sftp_stat(3)
will follow all symlinks, while libssh2_sftp_lstat(3)
will return data about the object encountered, even if that object
happens to be a symlink.

The LIBSSH2_SFTP_ATTRIBUTES struct looks like this:

~~~c
struct LIBSSH2_SFTP_ATTRIBUTES {
    /* If flags & ATTR_* bit is set, then the value in this struct will be
     * meaningful Otherwise it should be ignored
     */
    unsigned long flags;

    libssh2_uint64_t filesize;
    unsigned long uid;
    unsigned long gid;
    unsigned long permissions;
    unsigned long atime;
    unsigned long mtime;
};
~~~

# RETURN VALUE

Returns 0 on success or negative on failure. It returns LIBSSH2_ERROR_EAGAIN
when it would otherwise block. While LIBSSH2_ERROR_EAGAIN is a negative
number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to
be returned by the server.
