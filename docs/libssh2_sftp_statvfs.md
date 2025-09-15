---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_statvfs
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_init(3)
  - libssh2_sftp_open_ex(3)
---

# NAME

libssh2_sftp_statvfs, libssh2_sftp_fstatvfs - get file system statistics

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

int
libssh2_sftp_statvfs(LIBSSH2_SFTP *sftp, const char *path,
                     size_t path_len, LIBSSH2_SFTP_STATVFS *st);

int
libssh2_sftp_fstatvfs(LIBSSH2_SFTP_HANDLE *handle,
                      LIBSSH2_SFTP_STATVFS *st)
~~~

# DESCRIPTION

These functions provide statvfs(2)-like operations and require
statvfs@openssh.com and fstatvfs@openssh.com extension support on the server.

*sftp* - SFTP instance as returned by libssh2_sftp_init(3)

*handle* - SFTP File Handle as returned by libssh2_sftp_open_ex(3)

*path* - full path of any file within the mounted file system.

*path_len* - length of the full path.

*st* - Pointer to a LIBSSH2_SFTP_STATVFS structure to place file system
statistics into.

# DATA TYPES

LIBSSH2_SFTP_STATVFS is a typedefed struct that is defined as below

~~~c
struct _LIBSSH2_SFTP_STATVFS {
    libssh2_uint64_t  f_bsize;    /* file system block size */
    libssh2_uint64_t  f_frsize;   /* fragment size */
    libssh2_uint64_t  f_blocks;   /* size of fs in f_frsize units */
    libssh2_uint64_t  f_bfree;    /* # free blocks */
    libssh2_uint64_t  f_bavail;   /* # free blocks for non-root */
    libssh2_uint64_t  f_files;    /* # inodes */
    libssh2_uint64_t  f_ffree;    /* # free inodes */
    libssh2_uint64_t  f_favail;   /* # free inodes for non-root */
    libssh2_uint64_t  f_fsid;     /* file system ID */
    libssh2_uint64_t  f_flag;     /* mount flags */
    libssh2_uint64_t  f_namemax;  /* maximum filename length */
};
~~~

It is unspecified whether all members of the returned struct have meaningful
values on all file systems.

The field *f_flag* is a bit mask. Bits are defined as follows:

## LIBSSH2_SFTP_ST_RDONLY

Read-only file system.

## LIBSSH2_SFTP_ST_NOSUID

Set-user-ID/set-group-ID bits are ignored by **exec**(3).

# RETURN VALUE

Returns 0 on success or negative on failure. If used in non-blocking mode, it
returns LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_SFTP_PROTOCOL* - An invalid SFTP protocol response was
received on the socket, or an SFTP operation caused an errorcode to be returned
by the server.

# AVAILABILITY

Added in libssh2 1.2.6
