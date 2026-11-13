/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OSS-Fuzz target: exercise the private-key file parsers (pem.c and the
 * key-decode paths in openssl.c that they feed).
 *
 * Private key files are untrusted content: PEM armor parsing, base64
 * decoding, the OpenSSH new-format container (cipher/kdf name lists,
 * public/private key length fields) and the bcrypt_pbkdf passphrase KDF
 * all consume attacker-influencable bytes when a hostile key file is
 * loaded. The fuzz input is used directly as the key file blob; the first
 * byte selects the parser and whether a passphrase is applied.
 *
 * In-tree target: the PEM entry points are internal API declared in
 * libssh2_priv.h, reachable because -DLIBSSH2_TESTS is set for the
 * ossfuzz tests.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern "C" {
#include "libssh2.h"
#include "libssh2_priv.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    LIBSSH2_SESSION *session = NULL;
    const char *blob;
    size_t blob_len;
    unsigned char *decoded = NULL;
    size_t decoded_len = 0;
    size_t blob_offset = 0;
    struct string_buf *decrypted = NULL;
    const char *passphrase = NULL;
    char passbuf[16];
    int kind;

    if(size < 2)
        return 0;

    if(libssh2_init(0))
        return 0;

    session = libssh2_session_init();

    if(!session)
        goto EXIT_LABEL;

    /* byte 0: bit 0-1 selects the parser, bit 2 enables a passphrase */
    kind = data[0] & 0x03;
    blob = (const char *)data + 1;
    blob_len = size - 1;

    if(data[0] & 0x04) {
        memset(passbuf, 0, sizeof(passbuf));
        strncpy(passbuf, "fuzzpass", sizeof(passbuf) - 1);
        passphrase = passbuf;
    }

    if(kind == 0) {
        /* classic PEM armor */
        (void)ssh2_pem_parse(session,
                             "-----BEGIN RSA PRIVATE KEY-----",
                             "-----END RSA PRIVATE KEY-----",
                             NULL, blob, blob_len, passphrase,
                             &decoded, &decoded_len, &blob_offset);
    }
    else if(kind == 1) {
        /* OpenSSH new-format key container (bcrypt_pbkdf KDF) */
        (void)ssh2_openssh_pem_parse(session, NULL, blob, blob_len,
                                     passphrase, &decrypted);
    }
    else if(kind == 2) {
        /* encrypted classic PEM */
        (void)ssh2_pem_parse(session,
                             "-----BEGIN EC PRIVATE KEY-----",
                             "-----END EC PRIVATE KEY-----",
                             NULL, blob, blob_len, passphrase,
                             &decoded, &decoded_len, &blob_offset);
    }
    else {
        /* OpenSSH container, always with passphrase */
        (void)ssh2_openssh_pem_parse(session, NULL, blob, blob_len,
                                     "fuzzpass", &decrypted);
    }

    if(decoded)
        libssh2_free(session, decoded);

    if(decrypted)
        ssh2_string_buf_free(session, decrypted);

EXIT_LABEL:

    if(session)
        libssh2_session_free(session);

    return 0;
}
