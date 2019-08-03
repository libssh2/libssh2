#include "clar_libssh2.h"
#include "../userauth/userauth_helpers.h"

static LIBSSH2_SESSION *g_session;

void test_agent_auth__initialize(void)
{
    g_session = cl_ssh2_open_session_openssh(NULL, 1);
    cl_fixture_sandbox("publickeys");
}

void test_agent_auth__cleanup(void)
{
    cl_ssh2_close_connected_session();
    cl_fixture_cleanup("publickeys");
}

void test_agent_auth__forward_succeeds(void)
{
    LIBSSH2_CHANNEL *channel;

    cl_userauth_check_mech(g_session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(
        libssh2_userauth_publickey_fromfile_ex(
            g_session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
            RSA_KEYFILE_PUBLIC, RSA_KEYFILE_PRIVATE, NULL));

    channel = libssh2_channel_open_session(g_session);

    cl_ssh2_check(libssh2_channel_request_auth_agent(channel));

    libssh2_channel_free(channel);
}
