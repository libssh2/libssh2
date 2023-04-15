#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    return test_auth_pubkey(session, TEST_AUTH_SHOULDFAIL,
                            "libssh2", /* set in Dockerfile */
                            NULL,
                            "key_dsa_wrong.pub",
                            "key_dsa_wrong");
}
