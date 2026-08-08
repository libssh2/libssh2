/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "runner.h"

static const char EXPECTED_RSA_HOSTKEY[] =
    "AAAAB3NzaC1yc2EAAAABIwAAAQEArrr/JuJmaZligyfS8vcNur+mWR2ddDQtVdhHzdKU"
    "UoR6/Om6cvxpe61H1YZO1xCpLUBXmkki4HoNtYOpPB2W4V+8U4BDeVBD5crypEOE1+7B"
    "Am99fnEDxYIOZq2/jTP0yQmzCpWYS3COyFmkOL7sfX1wQMeW5zQT2WKcxC6FSWbhDqrB"
    "eNEGi687hJJoJ7YXgY/IdiYW5NcOuqRSWljjGS3dAJsHHWk4nJbhjEDXbPaeduMAwQU9"
    "i6ELfP3r+q6wdu0P4jWaoo3De1aYxnToV/ldXykpipON4NPamsb6Ph2qlJQKypq7J4iQ"
    "gkIIbCU1A31+4ExvcIVoxLQw/aTSbw==";

static const char EXPECTED_ECDSA_HOSTKEY[] =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+/syyeKJD9dC2ZH"
    "9Q7iJGReR4YM3rUCMsSynkyXojdfSClGCMY7JvWlt30ESjYvxoTfSRGx6WvaqYK/vPoYQ4=";

static const char EXPECTED_ED25519_HOSTKEY[] =
    "AAAAC3NzaC1lZDI1NTE5AAAAIO7Dhx/ox7Xoi/sg2GrR7j2x5NxvTGKnMH3wifd6UPCx";

int test(LIBSSH2_SESSION *session)
{
    int rc;
    size_t len, len_str;
    int type;
    size_t expected_len = 0;
    char *expected_hostkey = NULL;
    const char *hostkey;
    const char *hostkey_str;

    hostkey = libssh2_session_hostkey(session, &len, &type);
    if(!hostkey) {
        print_last_session_error("libssh2_session_hostkey()");
        return 1;
    }

    if(len < 4) {
        print_last_session_error("libssh2_session_hostkey() hostkey too short");
        return 1;
    }

    hostkey_str = hostkey + 4;
    len_str = len - 4;

    if(SSH2_IS_LITERAL(hostkey_str, len_str, "ssh-ed25519"))
        rc = ssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                EXPECTED_ED25519_HOSTKEY,
                                sizeof(EXPECTED_ED25519_HOSTKEY) - 1);
    else if(SSH2_IS_LITERAL(hostkey_str, len_str, "ecdsa-sha2-nistp256"))
        rc = ssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                EXPECTED_ECDSA_HOSTKEY,
                                sizeof(EXPECTED_ECDSA_HOSTKEY) - 1);
    else if(SSH2_IS_LITERAL(hostkey_str, len_str, "ssh-rsa"))
        rc = ssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                EXPECTED_RSA_HOSTKEY,
                                sizeof(EXPECTED_RSA_HOSTKEY) - 1);
    else {
        fprintf(stderr, "Unexpected type of hostkey: %d\n", type);
        return 1;
    }

    if(rc) {
        print_last_session_error("ssh2_base64_decode()");
        return 1;
    }

    if(len != expected_len) {
        fprintf(stderr, "Hostkey does not have the expected length %lu!=%lu\n",
                (unsigned long)len, (unsigned long)expected_len);
        return 1;
    }

    if(memcmp(hostkey, expected_hostkey, len)) {
        fprintf(stderr, "Hostkeys do not match\n");
        return 1;
    }

    return 0;
}
