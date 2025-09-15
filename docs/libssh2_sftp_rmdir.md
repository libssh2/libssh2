---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_sftp_rmdir
Section: 3
Source: libssh2
See-also:
  - libssh2_sftp_rmdir_ex(3)
---

# NAME

libssh2_sftp_rmdir - convenience macro for *libssh2_sftp_rmdir_ex(3)*

# SYNOPSIS

~~~c
#include <libssh2.h>
#include <libssh2_sftp.h>

#define libssh2_sftp_rmdir(sftp, path) \
    libssh2_sftp_rmdir_ex((sftp), (path), strlen(path))
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_sftp_rmdir_ex(3)*.

# RETURN VALUE

See *libssh2_sftp_rmdir_ex(3)*

# ERRORS

See *libssh2_sftp_rmdir_ex(3)*
