#include "clar_libssh2.h"
#include "userauth_helpers.h"

static LIBSSH2_SESSION *session;

void test_userauth_publickey__initialize(void)
{
    session = cl_ssh2_open_session_openssh(NULL);
    cl_fixture_sandbox("publickeys");
}

void test_userauth_publickey__cleanup(void)
{
    cl_ssh2_close_connected_session();
    cl_fixture_cleanup("publickeys");
}

void test_userauth_publickey__auth_fails_with_wrong_key(void)
{
    struct stat _stat;
    cl_must_pass(stat(WRONG_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(WRONG_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_fail(LIBSSH2_ERROR_AUTHENTICATION_FAILED,
                 libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        WRONG_KEYFILE_PUBLIC, WRONG_KEYFILE_PRIVATE,
        NULL));

    cl_assert_equal_i(0, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__dsa_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_DSA) && !LIBSSH2_DSA
    cl_skip();
#endif

    cl_must_pass(stat(DSA_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(DSA_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        DSA_KEYFILE_PUBLIC, DSA_KEYFILE_PRIVATE,
        NULL));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__ed25519_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_ED25519) && !LIBSSH2_ED25519
    cl_skip();
#endif

    cl_must_pass(stat(ED25519_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(ED25519_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        ED25519_KEYFILE_PUBLIC, ED25519_KEYFILE_PRIVATE,
        NULL));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__ed25519_mem_auth_ok(void)
{
    char *buffer = NULL;
    size_t len = 0;

#if defined(LIBSSH2_ED25519) && !LIBSSH2_ED25519
    cl_skip();
#endif

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    if(cl_ssh2_read_file(ED25519_KEYFILE_PRIVATE, &buffer, &len)) {
        cl_fail("Reading key file failed");
    }

    cl_ssh2_check(libssh2_userauth_publickey_frommemory(session,
        OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        NULL, 0, buffer, len, NULL));

    free(buffer);

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__ed25519_encrypted_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_ED25519) && !LIBSSH2_ED25519
    cl_skip();
#endif

    cl_must_pass(stat(ED25519_KEYFILE_ENC_PUBLIC, &_stat));
    cl_must_pass(stat(ED25519_KEYFILE_ENC_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        ED25519_KEYFILE_ENC_PUBLIC, ED25519_KEYFILE_ENC_PRIVATE,
        ED25519_KEYFILE_PASSWORD));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__rsa_encrypted_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_RSA) && !LIBSSH2_RSA
    cl_skip();
#endif

    cl_must_pass(stat(RSA_KEYFILE_ENC_PUBLIC, &_stat));
    cl_must_pass(stat(RSA_KEYFILE_ENC_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        RSA_KEYFILE_ENC_PUBLIC, RSA_KEYFILE_ENC_PRIVATE,
        RSA_KEYFILE_PASSWORD));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__rsa_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_RSA) && !LIBSSH2_RSA
    cl_skip();
#endif

    cl_must_pass(stat(RSA_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(RSA_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        RSA_KEYFILE_PUBLIC, RSA_KEYFILE_PRIVATE,
        NULL));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__rsa_openssh_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_RSA) && !LIBSSH2_RSA || !defined(LIBSSH2_OPENSSL)
    cl_skip();
#endif

    cl_must_pass(stat(RSA_OPENSSH_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(RSA_OPENSSH_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(
        session, OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        RSA_OPENSSH_KEYFILE_PUBLIC, RSA_OPENSSH_KEYFILE_PRIVATE,
        NULL));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__ecdsa_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_ECDSA) && !LIBSSH2_ECDSA
    cl_skip();
#endif

    cl_must_pass(stat(ECDSA_KEYFILE_PUBLIC, &_stat));
    cl_must_pass(stat(ECDSA_KEYFILE_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(session,
                                                OPENSSH_USERNAME,
                                                strlen(OPENSSH_USERNAME),
                                                ECDSA_KEYFILE_PUBLIC,
                                                ECDSA_KEYFILE_PRIVATE,
                                                NULL));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__ecdsa_mem_auth_ok(void)
{
    char *buffer = NULL;
    size_t len = 0;

#if defined(LIBSSH2_ECDSA) && !LIBSSH2_ECDSA
    cl_skip();
#endif

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    if(cl_ssh2_read_file(ECDSA_KEYFILE_PRIVATE, &buffer, &len)) {
        cl_fail("Reading key file failed");
    }

    cl_ssh2_check(libssh2_userauth_publickey_frommemory(session,
        OPENSSH_USERNAME, strlen(OPENSSH_USERNAME),
        NULL, 0, buffer, len, NULL));
    free(buffer);

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}

void test_userauth_publickey__ecdsa_encrypted_auth_ok(void)
{
    struct stat _stat;

#if defined(LIBSSH2_ECDSA) && !LIBSSH2_ECDSA
    cl_skip();
#endif

    cl_must_pass(stat(ECDSA_KEYFILE_ENC_PUBLIC, &_stat));
    cl_must_pass(stat(ECDSA_KEYFILE_ENC_PRIVATE, &_stat));

    cl_userauth_check_mech(session, OPENSSH_USERNAME, "publickey");

    cl_ssh2_check(libssh2_userauth_publickey_fromfile_ex(session,
                                                OPENSSH_USERNAME,
                                                strlen(OPENSSH_USERNAME),
                                                ECDSA_KEYFILE_ENC_PUBLIC,
                                                ECDSA_KEYFILE_ENC_PRIVATE,
                                                ECDSA_KEYFILE_ENC_PASSWORD));

    cl_assert_equal_i(1, libssh2_userauth_authenticated(session));
}
