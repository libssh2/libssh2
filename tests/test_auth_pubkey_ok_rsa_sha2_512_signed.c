/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "runner.h"

#include <stdlib.h>  /* for getenv() */

int test(LIBSSH2_SESSION *session)
{
#if LIBSSH2_RSA_SHA2
    const char *user = getenv("FIXTURE_USER");
    /* set in Dockerfile */
    return test_auth_pubkey(session, 0,
                            user ? user : "libssh2",
                            NULL,
                            "keys/id_rsa_sha2_512_signed-cert.pub",
#if defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
                            "keys/id_rsa_sha2_512_signed"
#else
                            "keys/id_rsa_sha2_512_signed_pem"
#endif
                            );
#else
    (void)session;
    return 0;
#endif
}
