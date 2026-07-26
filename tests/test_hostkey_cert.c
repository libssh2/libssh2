/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Test certificate hostkey verification. The server is configured (via
 * tests/openssh_server/sshd_config) to offer certificate hostkey
 * algorithms alongside the plain ones; FIXTURE_TEST_HOSTKEY selects which
 * one the client demands. This exercises the cert-aware init() paths in
 * src/hostkey.c that extract the inner public key from an OpenSSH
 * certificate blob (see libssh2 issue #2434 and PR #2064 for ed25519).
 */

#include "runner.h"

int test(LIBSSH2_SESSION *session)
{
    const char *hostkey;
    const char *want;
    size_t len;
    unsigned int name_len;
    int type;

    hostkey = libssh2_session_hostkey(session, &len, &type);
    if(!hostkey) {
        print_last_session_error("libssh2_session_hostkey()");
        return 1;
    }

    /* The negotiated hostkey type string lives at the start of the blob:
     *   uint32  name_len
     *   byte[n] name
     * Check it matches the algorithm we requested via FIXTURE_TEST_HOSTKEY. */
    if(len < 4) {
        fprintf(stderr, "Hostkey blob too short: %lu\n", (unsigned long)len);
        return 1;
    }

    want = getenv("FIXTURE_TEST_HOSTKEY");
    if(!want)
        want = "ssh-ed25519-cert-v01@openssh.com";

    name_len = ((unsigned int)(unsigned char)hostkey[0] << 24) |
               ((unsigned int)(unsigned char)hostkey[1] << 16) |
               ((unsigned int)(unsigned char)hostkey[2] << 8) |
               (unsigned int)(unsigned char)hostkey[3];
    if(name_len != (unsigned int)strlen(want) ||
       memcmp(hostkey + 4, want, name_len)) {
        fprintf(stderr, "Negotiated hostkey '%.*s' != expected '%s'\n",
                (int)name_len, hostkey + 4, want);
        return 1;
    }

    return 0;
}
