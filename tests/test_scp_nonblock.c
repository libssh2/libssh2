/* Copyright (C) The libssh2 project and its contributors.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct io_context {
    LIBSSH2_CHANNEL *channel;
    void *tracked_message;
    unsigned int recv_calls;
    unsigned int send_calls;
    unsigned int close_after_call;
    int tracked_message_freed;
};

static LIBSSH2_ALLOC_FUNC(tracking_alloc)
{
    (void)abstract;
    return malloc(count);
}

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

static void store_u32(unsigned char *buffer, uint32_t value)
{
    buffer[0] = (unsigned char)(value >> 24);
    buffer[1] = (unsigned char)(value >> 16);
    buffer[2] = (unsigned char)(value >> 8);
    buffer[3] = (unsigned char)value;
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
    store_u32(packet->data + 1, channel->local.id);
    store_u32(packet->data + 5, (uint32_t)payload_len);
    memcpy(packet->data + 9, payload, payload_len);
    packet->data_head = 9;
    channel->read_avail += payload_len;
    ssh2_list_add(&session->packets, &packet->node);
    return 0;
}

static LIBSSH2_CHANNEL *prepare_channel(LIBSSH2_SESSION *session)
{
    LIBSSH2_CHANNEL *channel = SSH2_CALLOC(session, sizeof(*channel));

    if(!channel)
        return NULL;

    channel->session = session;
    channel->local.id = 1;
    channel->remote.id = 2;
    channel->remote.window_size_initial = 1024 * 1024;
    channel->remote.window_size = 1024 * 1024;
    channel->remote.packet_size = 32768;
    ssh2_list_add(&session->channels, &channel->node);
    return channel;
}

static LIBSSH2_SESSION *prepare_session(struct io_context *ctx)
{
    LIBSSH2_SESSION *session =
        libssh2_session_init_ex(tracking_alloc, tracking_free, NULL, ctx);

    if(!session)
        return NULL;

    session->recv = synthetic_recv;
    session->send = synthetic_send;
    session->socket_fd = LIBSSH2_INVALID_SOCKET;
    session->socket_state = SSH2_SOCKET_CONNECTED;
    session->state = 0;
    libssh2_session_set_blocking(session, 0);

    ctx->channel = prepare_channel(session);
    if(!ctx->channel) {
        session->socket_state = SSH2_SOCKET_DISCONNECTED;
        libssh2_session_free(session);
        return NULL;
    }

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
    struct io_context ctx;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *result = NULL;
    const char *final_message;
    unsigned int api_calls = 0;
    unsigned int eagain_returns = 0;
    unsigned int cleanup_start_call = send_case ? 2 : 3;
    int rc = LIBSSH2_ERROR_NONE;
    int state_is_closing;
    int pointer_preserved;
    int failed = 0;

    memset(&ctx, 0, sizeof(ctx));
    /* Return EAGAIN during cleanup four times, keeping the test bounded. */
    ctx.close_after_call = cleanup_start_call + 3;
    session = prepare_session(&ctx);
    if(!session)
        return 1;

    if(queue_channel_data(session, ctx.channel, error_payload,
                          sizeof(error_payload))) {
        force_session_free(session);
        return 1;
    }

    if(send_case) {
        session->scpSend_channel = ctx.channel;
        session->scpSend_state = ssh2_NB_state_sent1;
        final_message = "Invalid ACK response from remote";
    }
    else {
        session->scpRecv_channel = ctx.channel;
        session->scpRecv_state = ssh2_NB_state_sent2;
        final_message = "Failed to recv file";
    }

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
            state_is_closing = send_case ?
                session->scpSend_state == ssh2_NB_state_error_closing :
                session->scpRecv_state == ssh2_NB_state_error_closing;
            pointer_preserved = send_case ?
                session->scpSend_channel == ctx.channel :
                session->scpRecv_channel == ctx.channel;
            if(result || !state_is_closing || !pointer_preserved ||
               !session->err_msg ||
               strcmp(session->err_msg, cleanup_error)) {
                fprintf(stderr,
                        "%s cleanup EAGAIN %u: result=%p state=%d "
                        "channel=%d message=%s\n",
                        send_case ? "send" : "recv", eagain_returns,
                        (void *)result, state_is_closing, pointer_preserved,
                        session->err_msg ? session->err_msg : "(null)");
                failed = 1;
                break;
            }
        }
    } while(rc == LIBSSH2_ERROR_EAGAIN && api_calls < 16);

    if(result || rc != LIBSSH2_ERROR_SCP_PROTOCOL ||
       !session->err_msg || strcmp(session->err_msg, final_message) ||
       api_calls != 5 || eagain_returns != 4 ||
       ctx.recv_calls != ctx.close_after_call || ctx.send_calls != 2 ||
       (send_case ? session->scpSend_state : session->scpRecv_state) !=
           ssh2_NB_state_idle ||
       (send_case ? session->scpSend_channel : session->scpRecv_channel) ||
       session->channels.first || session->channels.last ||
       session->packets.first || session->packets.last) {
        fprintf(stderr,
                "%s cleanup final: result=%p rc=%d message=%s calls=%u "
                "eagain=%u recv=%u send=%u state=%u channel=%p\n",
                send_case ? "send" : "recv", (void *)result, rc,
                session->err_msg ? session->err_msg : "(null)", api_calls,
                eagain_returns, ctx.recv_calls, ctx.send_calls,
                send_case ? (unsigned int)session->scpSend_state :
                            (unsigned int)session->scpRecv_state,
                (void *)(send_case ? session->scpSend_channel :
                                    session->scpRecv_channel));
        failed = 1;
    }

    force_session_free(session);
    return failed;
}

static int test_saved_error(int abandon_cleanup)
{
    static const char saved_message[] = "owned synthetic error";
    struct io_context ctx;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *result;
    int rc;
    int failed = 0;

    memset(&ctx, 0, sizeof(ctx));
    session = prepare_session(&ctx);
    if(!session)
        return 1;

    rc = libssh2_session_set_last_error(session, -1234, saved_message);
    if(rc != -1234 || !(session->err_flags & SSH2_ERR_FLAG_DUP)) {
        force_session_free(session);
        return 1;
    }
    ctx.tracked_message = SSH2_UNCONST(session->err_msg);

    ctx.channel->write_state = ssh2_NB_state_end;
    ctx.close_after_call = 1;
    session->scpRecv_channel = ctx.channel;
    session->scpRecv_state = ssh2_NB_state_sent1;

    result = libssh2_scp_recv2(session, "synthetic-file", NULL);
    rc = libssh2_session_last_errno(session);
    if(result || rc != LIBSSH2_ERROR_EAGAIN ||
       session->scpRecv_state != ssh2_NB_state_error_closing) {
        fprintf(stderr,
                "saved error first call: result=%p rc=%d state=%u\n",
                (void *)result, rc,
                (unsigned int)session->scpRecv_state);
        failed = 1;
    }

    if(!failed && !abandon_cleanup) {
        result = libssh2_scp_recv2(session, "synthetic-file", NULL);
        rc = libssh2_session_last_errno(session);
        if(result || rc != -1234 || !session->err_msg ||
           strcmp(session->err_msg, saved_message) ||
           !(session->err_flags & SSH2_ERR_FLAG_DUP) ||
           session->scpRecv_state != ssh2_NB_state_idle) {
            fprintf(stderr,
                    "saved error restore: result=%p rc=%d message=%s "
                    "state=%u\n",
                    (void *)result, rc,
                    session->err_msg ? session->err_msg : "(null)",
                    (unsigned int)session->scpRecv_state);
            failed = 1;
        }
    }

    force_session_free(session);
    if(!ctx.tracked_message_freed) {
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
