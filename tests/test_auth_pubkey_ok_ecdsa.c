#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
#if defined(LIBSSH2_OPENSSL)  /* FIXME: 1.1.1 or upper */
    /* configured in Dockerfile */
    return test_auth_pubkey(session, 0,
                            "libssh2",
                            NULL,
                            "key_ecdsa.pub",
                            "key_ecdsa");
#else
    (void)session;
    return 0;
#endif
}
