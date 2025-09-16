---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_connect
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_disconnect(3)
  - libssh2_agent_init(3)
---

# NAME

libssh2_agent_connect - connect to an ssh-agent

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_agent_connect(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

Connect to an ssh-agent running on the system.

Call **libssh2_agent_disconnect(3)** to close the connection after
you are doing using it.

# RETURN VALUE

Returns 0 if succeeded, or a negative value for error.

# AVAILABILITY

Added in libssh2 1.2
