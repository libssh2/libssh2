---
c: Copyright (C) Michel Gillet
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_agent_get_backend_name
Section: 3
Source: libssh2
See-also:
  - libssh2_agent_get_backend_list_size(3)
  - libssh2_agent_set_backend_to_use(3)
---

# NAME

libssh2_agent_get_backend_name - get the name of an ssh-agent backend

# SYNOPSIS

~~~c
#include <libssh2.h>

const char *libssh2_agent_get_backend_name(int idx);
~~~

# DESCRIPTION

*libssh2_agent_get_backend_name(3)* returns the human-readable name of the
ssh-agent backend at index *idx*. The index should be within the range
returned by *libssh2_agent_get_backend_list_size(3)*.

# RETURN VALUE

Returns a pointer to the backend name, or NULL if the index is invalid.

# AVAILABILITY
