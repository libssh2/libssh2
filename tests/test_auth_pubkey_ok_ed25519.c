#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    /* configured in Dockerfile */
    return test_auth_pubkey(session, 0,
                            "libssh2",
                            NULL,
                            "key_ed25519.pub",
                            "key_ed25519");
}
