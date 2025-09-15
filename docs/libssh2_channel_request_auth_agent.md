---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_channel_request_auth_agent
Section: 3
Source: libssh2
See-also:
  - libssh2_channel_open_ex(3)
  - libssh2_session_callback_set2(3)
---

# NAME

libssh2_channel_request_auth_agent - request agent forwarding for a session

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_channel_request_auth_agent(LIBSSH2_CHANNEL *channel);
~~~

# DESCRIPTION

Request that agent forwarding be enabled for this SSH session. This sends the
request over this specific channel, which causes the agent listener to be
started on the remote side upon success. This agent listener will then run
for the duration of the SSH session.

To use agent forwarding, libssh2_session_callback_set2(3)
must first be called to set **LIBSSH2_CALLBACK_AUTHAGENT**.
This callback will be invoked when the remote host opens a connection to the
local agent.

*channel* - Previously opened channel instance such as returned by
libssh2_channel_open_ex(3)

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.
