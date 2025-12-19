---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_direct_streamlocal_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_channel_direct_streamlocal_ex - Tunnel a UNIX socket connection through an SSH session

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_CHANNEL *
libssh2_channel_direct_streamlocal_ex(LIBSSH2_SESSION *session,
                                      const char *socket_path,
                                      const char *shost, int sport);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*socket_path* - UNIX socket to connect to using the SSH host as a proxy.

*shost* - Host to tell the SSH server the connection originated on.

*sport* - Port to tell the SSH server the connection originated from.

Tunnel a UNIX socket connection through the SSH transport via the remote host to
a third party. Communication from the client to the SSH server remains
encrypted, communication from the server to the 3rd party host travels
in cleartext.

# RETURN VALUE

Pointer to a newly allocated LIBSSH2_CHANNEL instance, or NULL on errors.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.
