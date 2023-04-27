#include "runner.h"

static const char *EXPECTED_DSA_HOSTKEY =
    "AAAAB3NzaC1kc3MAAACBALG8m0lOYn6246tYwPo37NpE1vWBIzP5RxBw9f++WYZePySE"
    "4vfN4DilJAht6U5NI2Pewv2ooCsEHl5J0xHevghQVOorf/GKqkvvfBtksPLX4ZRftr0T"
    "O8u16vFFIDCfGFkoOZ0tDJyMJsI5zPleaqTm0zcKdN6RTznGiYvS5+nHAAAAFQCdY5Ne"
    "tscpJuJTUmSLdq643CAy1QAAAIEAnq7m6eypXoyh/Ra3MF73KW6wbCbc9ptwGRhVZy/H"
    "njXkWOPBgaL8tqfvmi0BRtZvxXcMIdQrWty+iooATv4izMFzeGCQLZogRw93CR+sxp+u"
    "MF0OOVCz/1ykRmc42pTf1m/LCtLx7rGkNGQkhxdzo/k2hv5dQlR2S05Gfwsn+w4AAACA"
    "C/aTbUv3cTjTb1UV45OQ9z/6ygnohiGacx9QepLd3Vxq1RqlXFkOFs6aCfp25tLBc/Q+"
    "Q8GGuHA92TC4vTReTMVsYvmF1Q9XiApC+fN9eAMD0aZzp2eahmEsWLC0v2x6e/UvBVDu"
    "z/slGrDtfJuydzOBT9929wXd6lCyYSpxZGw=";

static const char *EXPECTED_RSA_HOSTKEY =
    "AAAAB3NzaC1yc2EAAAABIwAAAQEArrr/JuJmaZligyfS8vcNur+mWR2ddDQtVdhHzdKU"
    "UoR6/Om6cvxpe61H1YZO1xCpLUBXmkki4HoNtYOpPB2W4V+8U4BDeVBD5crypEOE1+7B"
    "Am99fnEDxYIOZq2/jTP0yQmzCpWYS3COyFmkOL7sfX1wQMeW5zQT2WKcxC6FSWbhDqrB"
    "eNEGi687hJJoJ7YXgY/IdiYW5NcOuqRSWljjGS3dAJsHHWk4nJbhjEDXbPaeduMAwQU9"
    "i6ELfP3r+q6wdu0P4jWaoo3De1aYxnToV/ldXykpipON4NPamsb6Ph2qlJQKypq7J4iQ"
    "gkIIbCU1A31+4ExvcIVoxLQw/aTSbw==";

static const char *EXPECTED_ECDSA_HOSTKEY =
    "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC+/syyeKJD9dC2ZH"
    "9Q7iJGReR4YM3rUCMsSynkyXojdfSClGCMY7JvWlt30ESjYvxoTfSRGx6WvaqYK/vPoYQ4=";

static const char *EXPECTED_ED25519_HOSTKEY =
    "AAAAC3NzaC1lZDI1NTE5AAAAIIxtdyg2ZRXE70UwyPVUH3UyfDBV8GX5cPF636P6hjom";

int test(LIBSSH2_SESSION *session)
{
    int rc;
    size_t len;
    int type;
    size_t expected_len = 0;
    char *expected_hostkey = NULL;

    const char *hostkey = libssh2_session_hostkey(session, &len, &type);
    if(!hostkey) {
        print_last_session_error("libssh2_session_hostkey");
        return 1;
    }

    if(type == LIBSSH2_HOSTKEY_TYPE_ED25519) {
        rc = _libssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                    EXPECTED_ED25519_HOSTKEY,
                                    strlen(EXPECTED_ED25519_HOSTKEY));
    }
    else if(type == LIBSSH2_HOSTKEY_TYPE_ECDSA_256) {
        rc = _libssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                    EXPECTED_ECDSA_HOSTKEY,
                                    strlen(EXPECTED_ECDSA_HOSTKEY));
    }
    else if(type == LIBSSH2_HOSTKEY_TYPE_RSA) {
        rc = _libssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                    EXPECTED_RSA_HOSTKEY,
                                    strlen(EXPECTED_RSA_HOSTKEY));
    }
    else if(type == LIBSSH2_HOSTKEY_TYPE_DSS) {
        rc = _libssh2_base64_decode(session, &expected_hostkey, &expected_len,
                                    EXPECTED_DSA_HOSTKEY,
                                    strlen(EXPECTED_DSA_HOSTKEY));
    }
    else {
        fprintf(stderr, "Unexpected type of hostkey: %i\n", type);
        return 1;
    }

    if(rc) {
        print_last_session_error("_libssh2_base64_decode");
        return 1;
    }

    if(len != expected_len) {
        fprintf(stderr, "Hostkey does not have the expected length %ld!=%ld\n",
                (unsigned long)len, (unsigned long)expected_len);
        return 1;
    }

    if(memcmp(hostkey, expected_hostkey, len) != 0) {
        fprintf(stderr, "Hostkeys do not match\n");
        return 1;
    }

    return 0;
}
