---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_publickey_frommemory
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_publickey_frommemory - authenticate a session with a public key, read from memory

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_publickey_frommemory(LIBSSH2_SESSION *session,
                                      const char *username,
                                      size_t username_len,
                                      const char *publickeydata,
                                      size_t publickeydata_len,
                                      const char *privatekeydata,
                                      size_t privatekeydata_len,
                                      const char *passphrase);
~~~

# DESCRIPTION

*session* - Session instance as returned by libssh2_session_init_ex(3)

*username* - Remote user name to authenticate as.

*username_len* - Length of username.

*publickeydata* - Buffer containing the contents of a public key file.

*publickeydata_len* - Length of public key data.

*privatekeydata* - Buffer containing the contents of a private key file.

*privatekeydata_len* - Length of private key data.

*passphrase* - Passphrase to use when decoding private key file.

Attempt public key authentication using either a public key file or a PEM
encoded private key file stored in memory. When providing a private key, the
public key is automatically extracted from it. When providing both, the
passed public key takes precedence.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED* - The username/public key
combination was invalid.

*LIBSSH2_ERROR_AUTHENTICATION_FAILED* - Authentication using the supplied
public key was not accepted.

# AVAILABILITY

libssh2_userauth_publickey_frommemory was added in libssh2 1.6.0
Supported with OpenSSL, WinCNG, mbedTLS, OS/400 crypto backends.
