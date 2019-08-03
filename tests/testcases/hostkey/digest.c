#include "clar_libssh2.h"

static LIBSSH2_SESSION *session;

static void calculate_digest(const char *hash, size_t hash_len, char *buffer,
                             size_t buffer_len)
{
    size_t i;
    char *p = buffer;
    char *end = buffer + buffer_len;

    for(i = 0; i < hash_len && p < end; ++i) {
        p += snprintf(p, end - p, "%02X", (unsigned char)hash[i]);
    }
}


void test_hostkey_digest__initialize_blocking(void)
{
    session = cl_ssh2_open_session_openssh(NULL, 1);
}

void test_hostkey_digest__initialize_nonblocking(void)
{
    session = cl_ssh2_open_session_openssh(NULL, 0);
}

void test_hostkey_digest__cleanup(void)
{
    cl_ssh2_close_connected_session();
}


static const char *EXPECTED_RSA_HOSTKEY =
    "AAAAB3NzaC1yc2EAAAABIwAAAQEArrr/JuJmaZligyfS8vcNur+mWR2ddDQtVdhHzdKU"
    "UoR6/Om6cvxpe61H1YZO1xCpLUBXmkki4HoNtYOpPB2W4V+8U4BDeVBD5crypEOE1+7B"
    "Am99fnEDxYIOZq2/jTP0yQmzCpWYS3COyFmkOL7sfX1wQMeW5zQT2WKcxC6FSWbhDqrB"
    "eNEGi687hJJoJ7YXgY/IdiYW5NcOuqRSWljjGS3dAJsHHWk4nJbhjEDXbPaeduMAwQU9"
    "i6ELfP3r+q6wdu0P4jWaoo3De1aYxnToV/ldXykpipON4NPamsb6Ph2qlJQKypq7J4iQ"
    "gkIIbCU1A31+4ExvcIVoxLQw/aTSbw==";

void test_hostkey_digest__rsa_base64_decode(void)
{
    size_t len;
    int type;
    unsigned int expected_len = 0;
    char *expected_hostkey = NULL;
    const char *hostkey;

    cl_ssh2_check_ptr(hostkey, libssh2_session_hostkey(session, &len, &type));

    cl_assert_(type != LIBSSH2_HOSTKEY_TYPE_UNKNOWN, "unknown hostkey");
    if(type != LIBSSH2_HOSTKEY_TYPE_RSA)
        cl_skip();

    cl_must_pass(libssh2_base64_decode(session,
                                       &expected_hostkey, &expected_len,
                                       EXPECTED_RSA_HOSTKEY,
                                       strlen(EXPECTED_RSA_HOSTKEY)));
    cl_assert_equal_i(expected_len, len);
    cl_assert_equal_i_(0,
                       memcmp(hostkey, expected_hostkey, len),
                       "Hostkeys do not match");
    libssh2_free(session, expected_hostkey);
}

static const char *EXPECTED_RSA_MD5_HASH_DIGEST =
    "0C0ED1A5BB10275F76924CE187CE5C5E";

static const char *EXPECTED_RSA_SHA1_HASH_DIGEST =
    "F3CD59E2913F4422B80F7B0A82B2B89EAE449387";

static const char *EXPECTED_RSA_SHA256_HASH_DIGEST =
    "92E3DA49DF3C7F99A828F505ED8239397A5D1F62914459760F878F7510F563A3";

static const int MD5_HASH_SIZE = 16;
static const int SHA1_HASH_SIZE = 20;
static const int SHA256_HASH_SIZE = 32;

void test_hostkey_digest__rsa_fingerprints(void)
{
    char buf[BUFSIZ];

    const char *md5_hash;
    const char *sha1_hash;
    const char *sha256_hash;
    int type;
    size_t len;
    const char *hostkey;

    cl_ssh2_check_ptr(hostkey, libssh2_session_hostkey(session, &len, &type));

    cl_assert_(type != LIBSSH2_HOSTKEY_TYPE_UNKNOWN, "unknown hostkey");
    if(type != LIBSSH2_HOSTKEY_TYPE_RSA)
        cl_skip();

    md5_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    cl_assert_(md5_hash != NULL,
               "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_MD5)");

    calculate_digest(md5_hash, MD5_HASH_SIZE, buf, BUFSIZ);
    cl_assert_equal_s(buf, EXPECTED_RSA_MD5_HASH_DIGEST);

    sha1_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    cl_assert_(sha1_hash != NULL,
               "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1)");

    calculate_digest(sha1_hash, SHA1_HASH_SIZE, buf, BUFSIZ);
    cl_assert_equal_s(buf, EXPECTED_RSA_SHA1_HASH_DIGEST);

    sha256_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
    cl_assert_(sha256_hash != NULL,
               "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA256)");

    calculate_digest(sha256_hash, SHA256_HASH_SIZE, buf, BUFSIZ);
    cl_assert_equal_s(buf, EXPECTED_RSA_SHA256_HASH_DIGEST);
}

static const char *EXPECTED_ECDSA_HOSTKEY =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+/syyeKJD9dC2ZH"
    "9Q7iJGReR4YM3rUCMsSynkyXojdfSClGCMY7JvWlt30ESjYvxoTfSRGx6WvaqYK/vPoYQ4=";

static const char *EXPECTED_ECDSA_MD5_HASH_DIGEST =
    "0402E4D897580BBC911379CBD88BCD3D";

static const char *EXPECTED_ECDSA_SHA1_HASH_DIGEST =
    "12FDAD1E3B31B10BABB00F2A8D1B9A62C326BD2F";

static const char *EXPECTED_ECDSA_SHA256_HASH_DIGEST =
    "56FCD975B166C3F0342D0036E44C311A86C0EAE40713B53FC776369BAE7F5264";

void test_hostkey_digest__ecdsa_base64_decode(void)
{
    size_t len;
    int type;
    unsigned int expected_len = 0;
    char *expected_hostkey = NULL;
    const char *hostkey;

    cl_ssh2_check_ptr(hostkey, libssh2_session_hostkey(session, &len, &type));

    cl_assert_(type != LIBSSH2_HOSTKEY_TYPE_UNKNOWN, "unknown hostkey");
    if(type != LIBSSH2_HOSTKEY_TYPE_ECDSA_256)
        cl_skip();

    cl_must_pass(libssh2_base64_decode(session,
                                       &expected_hostkey, &expected_len,
                                       EXPECTED_ECDSA_HOSTKEY,
                                       strlen(EXPECTED_ECDSA_HOSTKEY)));

    cl_assert_equal_i(expected_len, len);
    cl_assert_equal_i_(0,
                       memcmp(hostkey, expected_hostkey, len),
                       "Hostkeys do not match");
    libssh2_free(session, expected_hostkey);
}


void test_hostkey_digest__ecdsa_fingerprints(void)
{
    char buf[BUFSIZ];

    const char *md5_hash;
    const char *sha1_hash;
    const char *sha256_hash;
    int type;
    size_t len;
    const char *hostkey;

    cl_ssh2_check_ptr(hostkey, libssh2_session_hostkey(session, &len, &type));

    cl_assert_(type != LIBSSH2_HOSTKEY_TYPE_UNKNOWN, "unknown hostkey");
    if(type != LIBSSH2_HOSTKEY_TYPE_ECDSA_256)
        cl_skip();

    md5_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
    cl_assert_(md5_hash != NULL,
               "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_MD5)");

    calculate_digest(md5_hash, MD5_HASH_SIZE, buf, BUFSIZ);
    cl_assert_equal_s(buf, EXPECTED_ECDSA_MD5_HASH_DIGEST);

    sha1_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    cl_assert_(sha1_hash != NULL,
               "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1)");

    calculate_digest(sha1_hash, SHA1_HASH_SIZE, buf, BUFSIZ);
    cl_assert_equal_s(buf, EXPECTED_ECDSA_SHA1_HASH_DIGEST);

    sha256_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
    cl_assert_(sha256_hash != NULL,
               "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA256)");

    calculate_digest(sha256_hash, SHA256_HASH_SIZE, buf, BUFSIZ);
    cl_assert_equal_s(buf, EXPECTED_ECDSA_SHA256_HASH_DIGEST);
}
