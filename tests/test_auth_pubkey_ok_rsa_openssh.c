#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
#if defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
    /* set in Dockerfile */
    return test_auth_pubkey(session, 0,
                            "libssh2",
                            NULL,
                            "key_rsa_openssh.pub",
                            "key_rsa_openssh");
#else
    (void)session;
    return 0;
#endif
}
