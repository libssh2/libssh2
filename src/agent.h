#ifndef LIBSSH2_AGENT_H
#define LIBSSH2_AGENT_H
/* Copyright (C) Daiki Ueno
 * Copyright (C) Daniel Stenberg
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#if defined(_WIN32) && !defined(LIBSSH2_WINDOWS_UWP)
#define SSH2_AGENT_BACKEND_WIN32_PAGEANT "Pageant"
#endif
#ifdef _WIN32
#define SSH2_AGENT_BACKEND_WIN32_OPENSSH "OpenSSH"
#endif

#ifdef HAVE_SYS_UN_H
/* Use the existence of sys/un.h as a test if Unix domain socket (AF_UNIX)
   is supported. Windows also supports it via winsock*.h, but not used here
   at this time. */
#include <sys/un.h>
#define SSH2_AGENT_BACKEND_UNIX "Unix"
#endif

#endif /* LIBSSH2_AGENT_H */
