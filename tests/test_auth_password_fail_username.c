#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    return test_auth_password(session, TEST_AUTH_SHOULDFAIL,
                              "I am the wrong username",
                              "my test password"); /* set in Dockerfile */
}
