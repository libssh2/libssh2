---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_direct_tcpip
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_direct_tcpip_ex(3)
---

# NAME

libssh2_channel_direct_tcpip - convenience macro for *libssh2_channel_direct_tcpip_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_channel_direct_tcpip(LIBSSH2_SESSION *session,
                             const char *host, int port);
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_channel_direct_tcpip_ex(3)*.

# RETURN VALUE

See *libssh2_channel_direct_tcpip_ex(3)*

# ERRORS

See *libssh2_channel_direct_tcpip_ex(3)*
