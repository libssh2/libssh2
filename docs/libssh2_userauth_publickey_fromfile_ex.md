---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_publickey_fromfile_ex
Section: 3
Source: libssh2
See-also:
  - libssh2_session_init_ex(3)
---

# NAME

libssh2_userauth_publickey_fromfile_ex - authenticate a session with a public key, read from a file

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION *session,
                                       const char *username,
                                       unsigned int username_len,
                                       const char *publickey,
                                       const char *privatekey,
                                       const char *passphrase);
~~~

# DESCRIPTION

*session* - Session instance as returned by
**libssh2_session_init_ex(3)**

*username* - Pointer to user name to authenticate as.

*username_len* - Length of *username*.

*publickey* - Path name of the public key file.
(e.g. /etc/ssh/hostkey.pub). If libssh2 is built against OpenSSL, this option
can be set to NULL.

*privatekey* - Path name of the private key file. (e.g. /etc/ssh/hostkey)

*passphrase* - Passphrase to use when decoding *privatekey*.

Attempt public key authentication using either a public key file or a PEM
encoded private key file stored on disk. When providing a private key, the
public key is automatically extracted from it. When providing both, the
passed public key takes precedence.

# RETURN VALUE

Return 0 on success or negative on failure. It returns
LIBSSH2_ERROR_EAGAIN when it would otherwise block. While
LIBSSH2_ERROR_EAGAIN is a negative number, it is not really a failure per se.

# ERRORS

*LIBSSH2_ERROR_FILE* - An issue opening, reading or parsing the disk file.

*LIBSSH2_ERROR_ALLOC* - An internal memory allocation call failed.

*LIBSSH2_ERROR_SOCKET_SEND* - Unable to send data on socket.

*LIBSSH2_ERROR_SOCKET_TIMEOUT* -

*LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED* - The username/public key
combination was invalid.

*LIBSSH2_ERROR_AUTHENTICATION_FAILED* - Authentication using the supplied
public key was not accepted.
