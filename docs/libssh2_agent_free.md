---
c: Copyright (C) Daiki Ueno
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_free
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_disconnect(3)
  - libssh2_agent_init(3)
---

# NAME

libssh2_agent_free - free an ssh-agent handle

# SYNOPSIS

~~~c
#include <libssh2.h>

void
libssh2_agent_free(LIBSSH2_AGENT *agent);
~~~

# DESCRIPTION

Free an ssh-agent handle. This function also frees the internal
collection of public keys.

# RETURN VALUE

None.

# AVAILABILITY

Added in libssh2 1.2
