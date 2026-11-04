---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_symlink
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_symlink_ex(3)
---

# NAME

libssh2_sftp_symlink - convenience macro for *libssh2_sftp_symlink_ex(3)*

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

#define libssh2_sftp_symlink(sftp, orig, linkpath) \
    libssh2_sftp_symlink_ex(sftp, orig, strlen(orig), linkpath, \
                            strlen(linkpath), LIBSSH2_SFTP_SYMLINK)
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_sftp_symlink_ex(3)*.

On an OpenSSH server, *orig* is the destination stored in the symbolic
link, and *linkpath* is the pathname of the symbolic link to create.
The destination need not exist.

OpenSSH reverses the argument order specified by the SFTP version 3
draft. For a server following that draft order, supply the pathname of
the symbolic link as *orig* and its destination as *linkpath*. See
*libssh2_sftp_symlink_ex(3)* for details. libssh2 does not adjust the
argument order for the server.

# RETURN VALUE

See *libssh2_sftp_symlink_ex(3)*

# ERRORS

See *libssh2_sftp_symlink_ex(3)*
