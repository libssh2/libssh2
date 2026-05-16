/* Copyright (C) The libssh2 project and its contributors.
 *
 * regression test for #1672: every EAGAIN exit in send_existing() must
 * leave block_directions non-zero so the caller knows what to wait on.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"
#include "transport.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* fake a half-sent packet. returns the pointer to pass to
   _libssh2_transport_send() so it matches p->odata. */
static const unsigned char *arm_pending_packet(LIBSSH2_SESSION *session,
                                               const unsigned char *body,
                                               size_t body_len,
                                               size_t already_sent)
{
    struct transportpacket *p = &session->packet;

    assert(body_len <= sizeof(p->outbuf));
    assert(already_sent <= body_len);
    memcpy(p->outbuf, body, body_len);
    p->odata = p->outbuf;
    p->olen = body_len;
    p->ototal_num = (ssize_t)body_len;
    p->osent = already_sent;
    return p->odata;
}

static void disarm_pending(LIBSSH2_SESSION *session)
{
    struct transportpacket *p = &session->packet;
    p->odata = NULL;
    p->olen = 0;
    p->ototal_num = 0;
    p->osent = 0;
}

static int expect_eagain_outbound(LIBSSH2_SESSION *session, int rc,
                                  const char *label)
{
    int bd;

    if(rc != LIBSSH2_ERROR_EAGAIN) {
        fprintf(stderr,
                "%s: _libssh2_transport_send returned %d, expected EAGAIN\n",
                label, rc);
        return 1;
    }
    bd = libssh2_session_block_directions(session);
    if(!(bd & LIBSSH2_SESSION_BLOCK_OUTBOUND)) {
        fprintf(stderr,
                "%s: block_directions = 0x%x, expected OUTBOUND (0x%x)\n",
                label, bd, LIBSSH2_SESSION_BLOCK_OUTBOUND);
        return 1;
    }
    return 0;
}

/* caller hands send_existing a different (data, len) while p->olen > 0.
   relies on the address check firing before LIBSSH2_SEND; if that ever
   gets reordered, install stub_send here too. */
static int test_addr_mismatch(LIBSSH2_SESSION *session)
{
    static const unsigned char queued[] = "previously-queued packet";
    static const unsigned char other[]  = "different packet body";
    int rc;

    arm_pending_packet(session, queued, sizeof(queued) - 1, 0);
    session->socket_block_directions = 0;

    rc = _libssh2_transport_send(session, other, sizeof(other) - 1, NULL, 0);

    disarm_pending(session);
    return expect_eagain_outbound(session, rc, "addr_mismatch");
}

/* negative = stub returns this as a -errno, non-negative = bytes "sent". */
static ssize_t stub_bytes_to_return;

static LIBSSH2_SEND_FUNC(stub_send)
{
    (void)socket;
    (void)buffer;
    (void)flags;
    (void)abstract;
    if(stub_bytes_to_return < 0)
        return stub_bytes_to_return;
    /* clamp so we never claim more than asked for */
    return stub_bytes_to_return < (ssize_t)length
        ? stub_bytes_to_return : (ssize_t)length;
}

/* LIBSSH2_SEND returns -EAGAIN. pin the existing behavior. */
static int test_send_eagain(LIBSSH2_SESSION *session)
{
    static const unsigned char queued[] = "queued bytes for eagain path";
    const size_t len = sizeof(queued) - 1;
    const unsigned char *data;
    libssh2_cb_generic *prev_send;
    int rc;

    stub_bytes_to_return = -EAGAIN;
    prev_send = libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND,
                                              (libssh2_cb_generic *)stub_send);

    data = arm_pending_packet(session, queued, len, 0);
    session->socket_block_directions = 0;

    rc = _libssh2_transport_send(session, data, len, NULL, 0);

    disarm_pending(session);
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND, prev_send);
    return expect_eagain_outbound(session, rc, "send_eagain");
}

/* LIBSSH2_SEND returns a short count (partial send). */
static int test_partial_send(LIBSSH2_SESSION *session)
{
    static const unsigned char queued[] = "queued bytes for partial-send path";
    const size_t len = sizeof(queued) - 1;
    const unsigned char *data;
    libssh2_cb_generic *prev_send;
    int rc;

    stub_bytes_to_return = (ssize_t)(len / 2); /* accept half */
    prev_send = libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND,
                                              (libssh2_cb_generic *)stub_send);

    data = arm_pending_packet(session, queued, len, 0);
    session->socket_block_directions = 0;

    rc = _libssh2_transport_send(session, data, len, NULL, 0);

    disarm_pending(session);
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND, prev_send);
    return expect_eagain_outbound(session, rc, "partial_send");
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

    if(test_addr_mismatch(session) != 0)
        failures++;
    if(test_send_eagain(session) != 0)
        failures++;
    if(test_partial_send(session) != 0)
        failures++;

    libssh2_session_free(session);
    libssh2_exit();

    return failures ? 1 : 0;
}
