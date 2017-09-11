#include "session_fixture.h"
#include "libssh2_config.h"

#include <libssh2.h>

#include <stdio.h>

const char *EXPECTED_RSA_HOSTKEY =
    "AAAAB3NzaC1yc2EAAAABIwAAAQEArrr/JuJmaZligyfS8vcNur+mWR2ddDQtVdhHzdKU"
    "UoR6/Om6cvxpe61H1YZO1xCpLUBXmkki4HoNtYOpPB2W4V+8U4BDeVBD5crypEOE1+7B"
    "Am99fnEDxYIOZq2/jTP0yQmzCpWYS3COyFmkOL7sfX1wQMeW5zQT2WKcxC6FSWbhDqrB"
    "eNEGi687hJJoJ7YXgY/IdiYW5NcOuqRSWljjGS3dAJsHHWk4nJbhjEDXbPaeduMAwQU9"
    "i6ELfP3r+q6wdu0P4jWaoo3De1aYxnToV/ldXykpipON4NPamsb6Ph2qlJQKypq7J4iQ"
    "gkIIbCU1A31+4ExvcIVoxLQw/aTSbw==";

const char *EXPECTED_ECDSA_HOSTKEY =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBG3+G5vVjF0tfzSY8"
    "FQ5cDrbFX5VXc09bRKPU7DfBhimxgEvLpjyxXRogiTSC+gy1SxFAo4aI1pUY5jlC6xG4Lk=";

const char *EXPECTED_RSA_MD5_HASH_DIGEST = "0C0ED1A5BB10275F76924CE187CE5C5E";

const char *EXPECTED_RSA_SHA1_HASH_DIGEST =
    "F3CD59E2913F4422B80F7B0A82B2B89EAE449387";

const char *EXPECTED_RSA_SHA256_HASH_DIGEST = "92E3DA49DF3C7F99A828F505ED8239397A5D1F62914459760F878F7510F563A3";

const char *EXPECTED_ECDSA_MD5_HASH_DIGEST = "335F4A355BC42E2892C6A2C0DAA82583";

const char *EXPECTED_ECDSA_SHA1_HASH_DIGEST =
    "71229C4CE17DEFF2BB81906A6E2294B8F926F337";

const char *EXPECTED_ECDSA_SHA256_HASH_DIGEST = "69C90048605A864CA563DDD44511862C1732B1B458A935BCF22E9FF47AC2CCDB";

const int MD5_HASH_SIZE = 16;
const int SHA1_HASH_SIZE = 20;
const int SHA256_HASH_SIZE = 32;

static void calculate_digest(const char *hash, size_t hash_len, char *buffer,
                             size_t buffer_len)
{
    size_t i;
    char *p = buffer;
    char *end = buffer + buffer_len;

    for (i = 0; i < hash_len && p < end; ++i) {
        p += snprintf(p, end - p, "%02X", (unsigned char)hash[i]);
    }
}

int test(LIBSSH2_SESSION *session)
{
    char buf[BUFSIZ];

    const char *md5_hash;
    const char *sha1_hash;
    const char *sha256_hash;
    int type;
    size_t len;

    const char *hostkey = libssh2_session_hostkey(session, &len, &type);
    if (hostkey == NULL) {
        print_last_session_error("libssh2_session_hostkey");
        return 1;
    }

    if (type == LIBSSH2_HOSTKEY_TYPE_ECDSA) {

        md5_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
        if (md5_hash == NULL) {
            print_last_session_error(
                "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_MD5)");
            return 1;
        }

        calculate_digest(md5_hash, MD5_HASH_SIZE, buf, BUFSIZ);

        if (strcmp(buf, EXPECTED_ECDSA_MD5_HASH_DIGEST) != 0) {
            fprintf(stderr, "MD5 hash not as expected - digest %s != %s\n", buf,
                    EXPECTED_ECDSA_MD5_HASH_DIGEST);
            return 1;
        }

        sha1_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
        if (sha1_hash == NULL) {
            print_last_session_error(
                "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1)");
            return 1;
        }

        calculate_digest(sha1_hash, SHA1_HASH_SIZE, buf, BUFSIZ);

        if (strcmp(buf, EXPECTED_ECDSA_SHA1_HASH_DIGEST) != 0) {
            fprintf(stderr, "SHA1 hash not as expected - digest %s != %s\n", buf,
                    EXPECTED_ECDSA_SHA1_HASH_DIGEST);
            return 1;
        }

        sha256_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
        if (sha256_hash == NULL) {
            print_last_session_error(
                "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA256)");
            return 1;
        }

        calculate_digest(sha256_hash, SHA256_HASH_SIZE, buf, BUFSIZ);

        if (strcmp(buf, EXPECTED_ECDSA_SHA256_HASH_DIGEST) != 0) {
            fprintf(stderr, "SHA256 hash not as expected - digest %s != %s\n", buf,
                    EXPECTED_ECDSA_SHA256_HASH_DIGEST);
            return 1;
        }

    } else if ( type == LIBSSH2_HOSTKEY_TYPE_RSA ) {

        md5_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
        if (md5_hash == NULL) {
            print_last_session_error(
                "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_MD5)");
            return 1;
        }

        calculate_digest(md5_hash, MD5_HASH_SIZE, buf, BUFSIZ);

        if (strcmp(buf, EXPECTED_RSA_MD5_HASH_DIGEST) != 0) {
            fprintf(stderr, "MD5 hash not as expected - digest %s != %s\n", buf,
                    EXPECTED_RSA_MD5_HASH_DIGEST);
            return 1;
        }

        sha1_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
        if (sha1_hash == NULL) {
            print_last_session_error(
                "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA1)");
            return 1;
        }

        calculate_digest(sha1_hash, SHA1_HASH_SIZE, buf, BUFSIZ);

        if (strcmp(buf, EXPECTED_RSA_SHA1_HASH_DIGEST) != 0) {
            fprintf(stderr, "SHA1 hash not as expected - digest %s != %s\n", buf,
                    EXPECTED_RSA_SHA1_HASH_DIGEST);
            return 1;
        }

        sha256_hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256);
        if (sha256_hash == NULL) {
            print_last_session_error(
                "libssh2_hostkey_hash(LIBSSH2_HOSTKEY_HASH_SHA256)");
            return 1;
        }

        calculate_digest(sha256_hash, SHA256_HASH_SIZE, buf, BUFSIZ);

        if (strcmp(buf, EXPECTED_RSA_SHA256_HASH_DIGEST) != 0) {
            fprintf(stderr, "SHA256 hash not as expected - digest %s != %s\n", buf,
                    EXPECTED_RSA_SHA256_HASH_DIGEST);
            return 1;
        }
    } else {
        fprintf(stderr, "Unexpected type of hostkey: %i\n", type);
        return 1;
    }

    return 0;
}
