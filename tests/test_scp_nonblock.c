/* Copyright (C) The libssh2 project and its contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"
#include "misc.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if(!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", name, __LINE__, #condition); \
        failed = 1; \
        goto out; \
    } \
} while(0)

struct io_context {
    LIBSSH2_CHANNEL *channel;
    void *tracked_message;
    unsigned int recv_calls;
    unsigned int send_calls;
    unsigned int close_after_call;
    int tracked_message_freed;
};

static LIBSSH2_FREE_FUNC(tracking_free)
{
    struct io_context *ctx = *(struct io_context **)abstract;

    if(ptr == ctx->tracked_message)
        ctx->tracked_message_freed = 1;
    free(ptr);
}

static LIBSSH2_RECV_FUNC(synthetic_recv)
{
    struct io_context *ctx = *(struct io_context **)abstract;

    (void)socket;
    (void)buffer;
    (void)length;
    (void)flags;

    ctx->recv_calls++;
    if(ctx->close_after_call &&
       ctx->recv_calls >= ctx->close_after_call) {
        ctx->channel->remote.close = 1;
        ctx->channel->remote.eof = 1;
    }

    return -EAGAIN;
}

static LIBSSH2_SEND_FUNC(synthetic_send)
{
    struct io_context *ctx = *(struct io_context **)abstract;

    (void)socket;
    (void)buffer;
    (void)flags;

    ctx->send_calls++;
    return (ssize_t)length;
}

static int queue_channel_data(LIBSSH2_SESSION *session,
                              LIBSSH2_CHANNEL *channel,
                              const unsigned char *payload,
                              size_t payload_len)
{
    struct packet *packet = SSH2_CALLOC(session, sizeof(*packet));

    if(!packet)
        return -1;

    packet->data_len = 9 + payload_len;
    packet->data = SSH2_CALLOC(session, packet->data_len);
    if(!packet->data) {
        SSH2_FREE(session, packet);
        return -1;
    }

    packet->data[0] = SSH_MSG_CHANNEL_DATA;
    ssh2_htonu32(packet->data + 1, channel->local.id);
    ssh2_htonu32(packet->data + 5, (uint32_t)payload_len);
    memcpy(packet->data + 9, payload, payload_len);
    packet->data_head = 9;
    channel->read_avail += payload_len;
    ssh2_list_add(&session->packets, &packet->node);
    return 0;
}

static LIBSSH2_SESSION *prepare_session(struct io_context *ctx)
{
    LIBSSH2_SESSION *session =
        libssh2_session_init_ex(NULL, tracking_free, NULL, ctx);
    LIBSSH2_CHANNEL *channel;

    if(!session)
        return NULL;

    session->recv = synthetic_recv;
    session->send = synthetic_send;
    session->socket_fd = LIBSSH2_INVALID_SOCKET;
    session->socket_state = SSH2_SOCKET_CONNECTED;
    session->state = 0;
    libssh2_session_set_blocking(session, 0);

    channel = SSH2_CALLOC(session, sizeof(*channel));
    if(!channel) {
        session->socket_state = SSH2_SOCKET_DISCONNECTED;
        libssh2_session_free(session);
        return NULL;
    }
    channel->session = session;
    channel->local.id = 1;
    channel->remote.id = 2;
    channel->remote.window_size_initial = 1024 * 1024;
    channel->remote.window_size = 1024 * 1024;
    channel->remote.packet_size = 32768;
    ssh2_list_add(&session->channels, &channel->node);
    ctx->channel = channel;
    return session;
}

static void force_session_free(LIBSSH2_SESSION *session)
{
    if(session) {
        session->socket_state = SSH2_SOCKET_DISCONNECTED;
        (void)libssh2_session_free(session);
    }
}

static int test_error_cleanup_eagain(int send_case)
{
    static const unsigned char error_payload[] = {
        1, 'm', 'i', 's', 's', 'i', 'n', 'g', '\n'
    };
    static const char cleanup_error[] = "Would block closing SCP channel";
    const char *name = send_case ? "send cleanup" : "recv cleanup";
    struct io_context ctx = { 0 };
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *result = NULL;
    const char *final_message;
    ssh2_NB_states *state;
    LIBSSH2_CHANNEL **channel;
    unsigned int api_calls = 0;
    unsigned int eagain_returns = 0;
    unsigned int cleanup_start_call = send_case ? 2 : 3;
    int rc = LIBSSH2_ERROR_NONE;
    int failed = 0;

    /* Return EAGAIN during cleanup four times, keeping the test bounded. */
    ctx.close_after_call = cleanup_start_call + 3;
    session = prepare_session(&ctx);
    if(!session)
        return 1;

    CHECK(!queue_channel_data(session, ctx.channel, error_payload,
                             sizeof(error_payload)));
    state = send_case ? &session->scpSend_state : &session->scpRecv_state;
    channel = send_case ? &session->scpSend_channel :
                          &session->scpRecv_channel;
    *state = send_case ? ssh2_NB_state_sent1 : ssh2_NB_state_sent2;
    *channel = ctx.channel;
    final_message = send_case ? "Invalid ACK response from remote" :
                               "Failed to recv file";

    do {
        api_calls++;
        if(send_case)
            result = libssh2_scp_send64(session, "synthetic-file", 0644,
                                        1, 0, 0);
        else {
            libssh2_struct_stat file_info;

            memset(&file_info, 0, sizeof(file_info));
            result = libssh2_scp_recv2(session, "synthetic-file", &file_info);
        }

        rc = libssh2_session_last_errno(session);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
            eagain_returns++;
            CHECK(!result && *state == ssh2_NB_state_error_closing);
            CHECK(*channel == ctx.channel);
            CHECK(session->err_msg &&
                  !strcmp(session->err_msg, cleanup_error));
        }
    } while(rc == LIBSSH2_ERROR_EAGAIN && api_calls < 16);

    CHECK(!result && rc == LIBSSH2_ERROR_SCP_PROTOCOL);
    CHECK(session->err_msg && !strcmp(session->err_msg, final_message));
    CHECK(api_calls == 5 && eagain_returns == 4);
    CHECK(ctx.recv_calls == ctx.close_after_call && ctx.send_calls == 2);
    CHECK(*state == ssh2_NB_state_idle && !*channel);
    CHECK(!session->channels.first && !session->channels.last);
    CHECK(!session->packets.first && !session->packets.last);
out:
    force_session_free(session);
    return failed;
}

static int test_saved_error(int abandon_cleanup)
{
    static const char saved_message[] = "owned synthetic error";
    const char *name = abandon_cleanup ? "saved error teardown" :
                                        "saved error restore";
    struct io_context ctx = { 0 };
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *result;
    int rc;
    int failed = 0;

    session = prepare_session(&ctx);
    if(!session)
        return 1;

    rc = libssh2_session_set_last_error(session, -1234, saved_message);
    CHECK(rc == -1234 && (session->err_flags & SSH2_ERR_FLAG_DUP));
    ctx.tracked_message = SSH2_UNCONST(session->err_msg);

    ctx.channel->write_state = ssh2_NB_state_end;
    ctx.close_after_call = 1;
    session->scpRecv_channel = ctx.channel;
    session->scpRecv_state = ssh2_NB_state_sent1;

    result = libssh2_scp_recv2(session, "synthetic-file", NULL);
    rc = libssh2_session_last_errno(session);
    CHECK(!result && rc == LIBSSH2_ERROR_EAGAIN);
    CHECK(session->scpRecv_state == ssh2_NB_state_error_closing);

    if(!abandon_cleanup) {
        result = libssh2_scp_recv2(session, "synthetic-file", NULL);
        rc = libssh2_session_last_errno(session);
        CHECK(!result && rc == -1234);
        CHECK(session->err_msg && !strcmp(session->err_msg, saved_message));
        CHECK(session->err_flags & SSH2_ERR_FLAG_DUP);
        CHECK(session->scpRecv_state == ssh2_NB_state_idle);
    }
out:
    force_session_free(session);
    if(ctx.tracked_message && !ctx.tracked_message_freed) {
        fprintf(stderr, "saved SCP error was not freed during teardown\n");
        failed = 1;
    }

    return failed;
}

int main(void)
{
    int rc;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2_init() failed: %d\n", rc);
        return 1;
    }

    rc = test_error_cleanup_eagain(0);
    rc |= test_error_cleanup_eagain(1);
    rc |= test_saved_error(0);
    rc |= test_saved_error(1);

    libssh2_exit();
    return rc;
}
