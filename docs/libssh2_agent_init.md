---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_init
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_connect(3)
  - libssh2_agent_free(3)
---

# NAME

libssh2_agent_init - init an ssh-agent handle

# SYNOPSIS

~~~c
#include <libssh2.h>

LIBSSH2_AGENT *
libssh2_agent_init(LIBSSH2_SESSION *session);
~~~

# DESCRIPTION

Init an ssh-agent handle. Returns the handle to an internal
representation of an ssh-agent connection. After the successful
initialization, an application can call **libssh2_agent_connect(3)**
to connect to a running ssh-agent.

Call **libssh2_agent_free(3)** to free the handle again after you are
doing using it.

# RETURN VALUE

Returns a handle pointer or NULL if something went wrong. The returned handle
is used as input to all other ssh-agent related functions libssh2 provides.

# AVAILABILITY

Added in libssh2 1.2
