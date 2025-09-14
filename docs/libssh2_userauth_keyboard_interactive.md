---
c: Copyright (C) The libssh2 project and its contributors.
SPDX-License-Identifier: BSD-3-Clause
Title: libssh2_userauth_keyboard_interactive
Section: 3
Source: libssh2
See-also:
  - libssh2_userauth_keyboard_interactive_ex(3)
---

# NAME

libssh2_userauth_keyboard_interactive - convenience macro for *libssh2_userauth_keyboard_interactive_ex(3)* calls

# SYNOPSIS

~~~c
#include <libssh2.h>

int
libssh2_userauth_keyboard_interactive(LIBSSH2_SESSION* session,
                                      const char *username,
                 LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC((*response_callback)));
~~~

# DESCRIPTION

This is a macro defined in a public libssh2 header file that is using the
underlying function *libssh2_userauth_keyboard_interactive_ex(3)*.

# RETURN VALUE

See *libssh2_userauth_keyboard_interactive_ex(3)*

# ERRORS

See *libssh2_userauth_keyboard_interactive_ex(3)*
