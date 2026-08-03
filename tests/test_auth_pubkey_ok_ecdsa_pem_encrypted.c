/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
#if LIBSSH2_ECDSA && LIBSSH2_MD5_PEM && LIBSSH2_AES_CBC
    /* set in Dockerfile */
    return test_auth_pubkey(session, 0,
                            "libssh2",
                            "libssh2",
                            "keys/id_ecdsa_pem_encrypted.pub",
                            "keys/id_ecdsa_pem_encrypted");
#else
    (void)session;
    return 0;
#endif
}
