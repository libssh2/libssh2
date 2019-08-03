#include "clar_libssh2.h"
#include "userauth_helpers.h"

static const char *WRONG_USERNAME = "i dont exist";
static const char *WRONG_PASSWORD = "i'm not the password";

static LIBSSH2_SESSION *session;

void test_userauth_password__initialize(void)
{
    session = cl_ssh2_open_session_openssh(NULL);
}

void test_userauth_password__cleanup(void)
{
    cl_ssh2_close_connected_session();
}

void test_userauth_password__auth_fails_with_wrong_username(void)
{
    cl_userauth_check_mech(session, WRONG_USERNAME, "password");

    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED,
        libssh2_userauth_password_ex(session,
            WRONG_USERNAME, strlen(WRONG_USERNAME),
            OPENSSH_PASSWORD, strlen(OPENSSH_PASSWORD),
            NULL));

    cl_assert_equal_i(0, libssh2_userauth_authenticated(session));
}

void test_userauth_password__auth_fails_with_wrong_password(void)
{
    cl_userauth_check_mech(session, OPENSSH_USERNAME, "password");

    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED,
        libssh2_userauth_password_ex(session,
        OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        WRONG_PASSWORD, strlen(WRONG_PASSWORD),
        NULL));

    cl_assert_equal_i(0, libssh2_userauth_authenticated(session));
}

void test_userauth_password__auth_succeeds_with_correct_credentials(void)
{
    cl_userauth_check_mech(session, OPENSSH_USERNAME, "password");

    cl_ssh2_check(libssh2_userauth_password_ex(session,
        OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        OPENSSH_PASSWORD, strlen(OPENSSH_PASSWORD),
        NULL));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}
