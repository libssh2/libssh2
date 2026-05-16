/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"
#include "transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Regression test for libssh2 #1672 / send_existing "Address is different".
 *
 * If a write is interrupted with bytes still queued in p->outbuf and the
 * next _libssh2_transport_send() arrives with a different data pointer
 * (typical when an internal kex packet or another channel's write races
 * with the original sender), send_existing() returns LIBSSH2_ERROR_EAGAIN.
 * Without this fix, socket_block_directions stayed at 0 and the caller
 * had no direction to wait on, deadlocking on epoll/select. */
static int test_send_existing_addr_mismatch(LIBSSH2_SESSION *session)
{
    static const unsigned char pending[] = "previously-queued packet";
    static const unsigned char other[]   = "different packet body";
    struct transportpacket *p = &session->packet;
    int rc;
    int bd;

    /* simulate a partially-sent packet still pending in outbuf */
    p->odata = pending;
    p->olen = sizeof(pending) - 1;
    p->ototal_num = (ssize_t)(sizeof(pending) - 1);
    p->osent = 0;

    /* start from a clean direction mask, like a freshly-handshaked session */
    session->socket_block_directions = 0;

    /* call with a different (data, len) — must hit the "Address is
       different" branch in send_existing() before any socket I/O */
    rc = _libssh2_transport_send(session, other, sizeof(other) - 1, NULL, 0);

    if(rc != LIBSSH2_ERROR_EAGAIN) {
        fprintf(stderr,
                "_libssh2_transport_send() returned %d, expected "
                "LIBSSH2_ERROR_EAGAIN (%d)\n",
                rc, LIBSSH2_ERROR_EAGAIN);
        return 1;
    }

    bd = libssh2_session_block_directions(session);
    if(!(bd & LIBSSH2_SESSION_BLOCK_OUTBOUND)) {
        fprintf(stderr,
                "block_directions = 0x%x after EAGAIN, expected OUTBOUND "
                "(0x%x) to be set\n",
                bd, LIBSSH2_SESSION_BLOCK_OUTBOUND);
        return 1;
    }

    /* clear the planted state so libssh2_session_free() doesn't trip */
    p->odata = NULL;
    p->olen = 0;
    p->ototal_num = 0;

    return 0;
}

int main(int argc, char *argv[])
{
    LIBSSH2_SESSION *session;
    int rc;
    int failures = 0;
    (void)argv;
    (void)argc;

    rc = libssh2_init(LIBSSH2_INIT_NO_CRYPTO);
    if(rc) {
        fprintf(stderr, "libssh2_init() failed: %d\n", rc);
        return 1;
    }

    session = libssh2_session_init();
    if(!session) {
        fprintf(stderr, "libssh2_session_init() failed\n");
        libssh2_exit();
        return 1;
    }

    if(test_send_existing_addr_mismatch(session) != 0)
        failures++;

    libssh2_session_free(session);
    libssh2_exit();

    return failures ? 1 : 0;
}
