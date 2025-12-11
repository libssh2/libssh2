---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_gsspi_with_mic_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_gsspi_with_mic_ex - authenticate a session with gssapi-with-mic

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_gsspi_with_mcic_ex(LIBSSH2_SESSION *session,
                                    const char *username,
                                    unsigned int username_len,
                                    const char *hostname,
                                    unsigned int hostname_len,
                                    int delegation_flag);

#define libssh2_userauth_gssapi_with_mic(session, username, hostname \
     libssh2_userauth_gssapi_with_mic_ex((session), (username), \
                                         strlen(username), \
                                         (hostname, strlen(hostname, 0)
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*username* - Name of user to attempt gssapi-with-mic authentication for.

*username_len* - Length of username parameter.

*hostname* - Hostname for connection.

*hostname_len* - Length of hostname parameter.

*delegation_flag - Flag to indicate the delegated credential can be used on the host.

Attempt gssapi-with-mic authentication. Note that username must be user@REALM
where REALM is the FQDN of the Windows domain and must be in upper case.
hostname must be FQDN. The client and the SSH-server must have joined the domain
and have a valid Kerberos ticket.

# RETURN VALUE

Return 0 on success or negative on failure. A partial successful 
authentication returns LIBSSH2_ERROR_PARTIAL_SUCCESS and further 
authentication is needed. It returns LIBSSH2_ERROR_EAGAIN when it
would otherwise block. While LIBSSH2_ERROR_PARTIAL_SUCCESS and
LIBSSH2_ERROR_EAGAIN are negative numbers, they are not really failures per se.

# ERRORS

Some of the errors this function may return include:

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_PASSWORD_EXPIRED* -

*LIBSSH2_ERROR_AUTHENTICATION_FAILED* - failed, invalid username
or Kerberos ticket invalid.

*LIBSSH2_ERROR_GSSAPI_FAILURE* - An error during the GSSAPI exchange.
