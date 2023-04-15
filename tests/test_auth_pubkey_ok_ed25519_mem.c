#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    /* configured in Dockerfile */
    return test_auth_pubkey(session, TEST_AUTH_FROMMEM,
                            "libssh2",
                            NULL,
                            NULL,
                            "key_ed25519");
}
