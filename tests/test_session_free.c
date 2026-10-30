/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static int test_send_calls;
static int test_close_cb_calls;
static int test_close_cb_local_close;
static int test_alloc_outstanding;

static void *test_alloc(size_t count, void **abstract)
{
    void *ptr = malloc(count);
    (void)abstract;
    if(ptr)
        test_alloc_outstanding++;
    return ptr;
}

static void test_free(void *ptr, void **abstract)
{
    (void)abstract;
    if(ptr)
        test_alloc_outstanding--;
    free(ptr);
}

static void *test_realloc(void *ptr, size_t count, void **abstract)
{
    (void)abstract;
    if(!ptr) {
        void *newptr = malloc(count);
        if(newptr)
            test_alloc_outstanding++;
        return newptr;
    }
    return realloc(ptr, count);
}

static ssize_t test_send_cb(libssh2_socket_t socket, const void *buffer,
                            size_t length, int flags, void **abstract)
{
    (void)socket;
    (void)buffer;
    (void)length;
    (void)flags;
    (void)abstract;
    test_send_calls++;
    return -EAGAIN;
}

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type"
#if __has_warning("-Wcast-function-type-strict")
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
#endif
static void test_set_send_callback(LIBSSH2_SESSION *session)
{
    (void)libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND,
                                        (libssh2_cb_generic *)test_send_cb);
}
#ifdef __clang__
#pragma clang diagnostic pop
#endif

static void test_channel_close_cb(LIBSSH2_SESSION *session,
                                  void **session_abstract,
                                  LIBSSH2_CHANNEL *channel,
                                  void **channel_abstract)
{
    (void)session;
    (void)session_abstract;
    (void)channel_abstract;
    test_close_cb_calls++;
    test_close_cb_local_close = channel->local.close != 0;
}

static int test_session_free_nonblocking(void)
{
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    int rc;

    test_alloc_outstanding = 0;
    session = libssh2_session_init_ex(test_alloc, test_free, test_realloc,
                                      NULL);
    if(!session) {
        fprintf(stderr, "libssh2_session_init_ex() failed\n");
        return 1;
    }

    test_set_send_callback(session);
    libssh2_session_set_blocking(session, 0);
    session->socket_state = SSH2_SOCKET_CONNECTED;

    channel = SSH2_CALLOC(session, sizeof(*channel));
    if(!channel) {
        fprintf(stderr, "Unable to allocate test channel\n");
        libssh2_session_free(session);
        return 1;
    }

    channel->session = session;
    channel->close_cb = test_channel_close_cb;
    ssh2_list_add(&session->channels, &channel->node);

    if(test_alloc_outstanding < 2) {
        fprintf(stderr,
                "allocation tracking did not see session and channel\n");
        libssh2_session_free(session);
        return 1;
    }

    test_send_calls = 0;
    test_close_cb_calls = 0;
    test_close_cb_local_close = 0;

    rc = libssh2_session_free(session);
    if(rc || test_send_calls || test_close_cb_calls != 1 ||
       !test_close_cb_local_close || test_alloc_outstanding) {
        fprintf(stderr,
                "nonblocking session_free: rc=%d send=%d close_cb=%d "
                "local.close=%d outstanding=%d\n",
                rc, test_send_calls, test_close_cb_calls,
                test_close_cb_local_close, test_alloc_outstanding);
        return 1;
    }

    return 0;
}

int main(void)
{
    int rc;

    if(libssh2_init(0)) {
        fprintf(stderr, "libssh2_init() failed\n");
        return 1;
    }

    rc = test_session_free_nonblocking();
    libssh2_exit();
    return rc;
}
