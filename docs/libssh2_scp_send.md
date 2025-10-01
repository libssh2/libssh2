---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_scp_send
Section: 3
Source: libssh2
See-also:
  - libssh2_scp_send64(3)
  - libssh2_scp_send_ex(3)
---

# NAME

libssh2_scp_send - convenience macro for *libssh2_scp_send_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_scp_send(LIBSSH2_SESSION *session, const char *path,
                 int mode, size_t size);
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_scp_send_ex(3)*.

This macro has been deemed deprecated since libssh2 1.2.6. See
*libssh2_scp_send64(3)*.

# RETURN VALUE

See *libssh2_scp_send_ex(3)*

# ERRORS

See *libssh2_scp_send_ex(3)*
