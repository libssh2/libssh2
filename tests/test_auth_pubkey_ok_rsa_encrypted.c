#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    /* configured in Dockerfile */
    return test_auth_pubkey(session, 0,
                            "libssh2",
                            "libssh2",
                            "key_rsa_encrypted.pub",
                            "key_rsa_encrypted");
}
