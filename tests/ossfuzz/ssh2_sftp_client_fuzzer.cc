/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OSS-Fuzz target: drive the libssh2 SFTP client (sftp.c) against a
 * scripted, attacker-controlled "server".
 *
 * The SFTP reply parsers (attribute decoding, name lists, status codes,
 * handle bookkeeping, statvfs decoding, the symlink/readdir paths) consume
 * bytes chosen entirely by the SSH server. A real client only reaches them
 * after a cryptographically valid key exchange, which a byte-level fuzzer
 * cannot produce, so sftp.c never runs under the handshake-only target.
 *
 * This harness removes the crypto barrier: the session never processes
 * NEWKEYS, the transport stays in plaintext mode, and the fuzz input is a
 * script of SFTP replies that the harness delivers as SSH_MSG_CHANNEL_DATA
 * packets over a socketpair while driving the public SFTP API in
 * nonblocking mode. The bootstrap (channel open confirmation + SSH_FXP_VERSION)
 * is fixed; everything after is attacker-controlled.
 *
 * In-tree target: uses internal declarations under src/ to read the
 * per-operation request ids and to reach the channel right after
 * libssh2_sftp_init() has sent its open request.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "libssh2.h"
#include "libssh2_sftp.h"
#include "libssh2_priv.h"
#include "sftp.h"
#include "channel.h"
}

/* SSH message types we emit */
#define MSG_CHANNEL_OPEN_CONFIRMATION           91
#define MSG_CHANNEL_DATA                        94
#define MSG_CHANNEL_CLOSE                       97
#define MSG_CHANNEL_SUCCESS                     99

/* SFTP packet types (private constants, mirroring src/sftp.c) */
#define SSH_FXP_INIT                            1
#define SSH_FXP_VERSION                         2
#define SSH_FXP_STATUS                          101
#define SSH_FXP_HANDLE                          102
#define SSH_FXP_DATA                            103
#define SSH_FXP_NAME                            104
#define SSH_FXP_ATTRS                           105
#define SSH_FXP_EXTENDED_REPLY                  201

/* Read one big-endian uint16/uint32 from the fuzz buffer */
static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* Write one SSH binary packet (plaintext, no blocks/MAC) to the peer end of
 * the socketpair: [u32 packet_length][u8 pad_len][payload][padding] */
static void ssh_send(int fd, const unsigned char *payload, size_t len)
{
    unsigned char hdr[5];
    unsigned char pad[32];
    uint32_t pkt_len;
    uint8_t pad_len = 4;
    ssize_t rc;

    if(len > 32768)
        return;

    pkt_len = (uint32_t)(1 + pad_len + len);
    hdr[0] = (unsigned char)(pkt_len >> 24);
    hdr[1] = (unsigned char)(pkt_len >> 16);
    hdr[2] = (unsigned char)(pkt_len >> 8);
    hdr[3] = (unsigned char)pkt_len;
    hdr[4] = pad_len;

    rc = send(fd, hdr, sizeof(hdr), MSG_NOSIGNAL);
    if(rc != (ssize_t)sizeof(hdr))
        return;
    rc = send(fd, payload, len, MSG_NOSIGNAL);
    if(rc != (ssize_t)len)
        return;
    memset(pad, 0, sizeof(pad));
    (void)send(fd, pad, pad_len, MSG_NOSIGNAL);
}

/* Deliver an SFTP message as SSH_MSG_CHANNEL_DATA for the channel:
 * SSH payload is [u8 94][u32 recipient][string frame] with
 * frame = [u32 len][u8 type][u32 request_id][body]. */
static void sftp_deliver(int fd, uint32_t local_id, uint8_t type,
                         uint32_t request_id,
                         const uint8_t *body, size_t body_len)
{
    unsigned char *payload;
    unsigned char *p;
    uint32_t frame_len = (uint32_t)(1 + 4 + body_len);
    uint32_t data_len = (uint32_t)(4 + 4 + 4 + frame_len);
    size_t payload_len = (size_t)(1 + 4 + 4 + data_len);

    if(body_len > 4096)
        return;

    payload = (unsigned char *)calloc(1, payload_len);
    if(!payload)
        return;

    p = payload;
    *p++ = MSG_CHANNEL_DATA;
    *p++ = (unsigned char)(local_id >> 24);
    *p++ = (unsigned char)(local_id >> 16);
    *p++ = (unsigned char)(local_id >> 8);
    *p++ = (unsigned char)local_id;
    *p++ = (unsigned char)(data_len >> 24);
    *p++ = (unsigned char)(data_len >> 16);
    *p++ = (unsigned char)(data_len >> 8);
    *p++ = (unsigned char)data_len;
    *p++ = (unsigned char)(frame_len >> 24);
    *p++ = (unsigned char)(frame_len >> 16);
    *p++ = (unsigned char)(frame_len >> 8);
    *p++ = (unsigned char)frame_len;
    *p++ = type;
    *p++ = (unsigned char)(request_id >> 24);
    *p++ = (unsigned char)(request_id >> 16);
    *p++ = (unsigned char)(request_id >> 8);
    *p++ = (unsigned char)request_id;

    if(body_len) {
        memcpy(p, body, body_len);
        p += body_len;
    }

    ssh_send(fd, payload, payload_len);
    free(payload);
}

/* Fixed bootstrap: libssh2_sftp_init() runs a three-step nonblocking
 * handshake and each step needs its server answer before the next can
 * proceed, so the answers are fed in order while retrying:
 *   1. SSH_MSG_CHANNEL_OPEN -> SSH_MSG_CHANNEL_OPEN_CONFIRMATION
 *   2. SSH_MSG_CHANNEL_REQUEST "subsystem" "sftp" -> SSH_MSG_CHANNEL_SUCCESS
 *   3. SSH_FXP_INIT -> SSH_FXP_VERSION (protocol version 3)
 * Returns 1 and sets *sftp_out on success, 0 on failure. */
static int sftp_bootstrap(LIBSSH2_SESSION *session, int fd,
                          LIBSSH2_SFTP **sftp_out)
{
    unsigned char conf[17];
    unsigned char success[5];
    uint32_t win = 0x200000;
    uint32_t maxpkt = 32768;
    uint32_t local_id;
    int fed_open = 0;
    int fed_success = 0;
    int fed_version = 0;
    int tries;

    local_id = ((LIBSSH2_CHANNEL *)ssh2_list_first(
                    &session->channels))->local.id;

    /* SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
     * [recipient][sender][initial window][max packet] */
    conf[0] = MSG_CHANNEL_OPEN_CONFIRMATION;
    conf[1] = (unsigned char)(local_id >> 24);
    conf[2] = (unsigned char)(local_id >> 16);
    conf[3] = (unsigned char)(local_id >> 8);
    conf[4] = (unsigned char)local_id;
    conf[5] = 0;
    conf[6] = 0;
    conf[7] = 0;
    conf[8] = 7; /* server-side id */
    conf[9] = (unsigned char)(win >> 24);
    conf[10] = (unsigned char)(win >> 16);
    conf[11] = (unsigned char)(win >> 8);
    conf[12] = (unsigned char)win;
    conf[13] = (unsigned char)(maxpkt >> 24);
    conf[14] = (unsigned char)(maxpkt >> 16);
    conf[15] = (unsigned char)(maxpkt >> 8);
    conf[16] = (unsigned char)maxpkt;

    /* SSH_MSG_CHANNEL_SUCCESS: [recipient] */
    success[0] = MSG_CHANNEL_SUCCESS;
    success[1] = (unsigned char)(local_id >> 24);
    success[2] = (unsigned char)(local_id >> 16);
    success[3] = (unsigned char)(local_id >> 8);
    success[4] = (unsigned char)local_id;

    for(tries = 0; tries < 64; tries++) {
        *sftp_out = libssh2_sftp_init(session);

        if(*sftp_out)
            return 1;

        if(session->err_code != LIBSSH2_ERROR_EAGAIN)
            return 0;

        if(!fed_open) {
            ssh_send(fd, conf, sizeof(conf));
            fed_open = 1;
        }
        else if(!fed_success) {
            ssh_send(fd, success, sizeof(success));
            fed_success = 1;
        }
        else if(!fed_version) {
            /* SSH_FXP_VERSION as channel data: frame [u32 5][u8 2][u32 3].
             * The FXP_VERSION reply has no request id - bytes 5..8 of the
             * frame are the protocol version itself, so pass it in the
             * request_id slot with an empty body. */
            sftp_deliver(fd, local_id, SSH_FXP_VERSION, 3, NULL, 0);
            fed_version = 1;
        }
    }

    return 0;
}

/* Op codes: which client call to drive with the record's reply */
#define OP_OPEN           1
#define OP_READDIR        2
#define OP_STAT           3
#define OP_SETSTAT        4
#define OP_READ           5
#define OP_WRITE          6
#define OP_CLOSE          7
#define OP_UNLINK         8
#define OP_MKDIR          9
#define OP_RMDIR          10
#define OP_RENAME         11
#define OP_POSIX_RENAME   12
#define OP_SYMLINK        13
#define OP_STATVFS        14
#define OP_FSTATVFS       15
#define OP_FSYNC          16
#define OP_REALPATH       17
#define OP_READLINK       18
#define OP_FSTAT          19

/* The request id the pending operation expects in its reply */
static uint32_t op_request_id(LIBSSH2_SFTP *sftp, LIBSSH2_SFTP_HANDLE *h,
                              uint8_t op)
{
    switch(op) {
    case OP_OPEN:
        return sftp->open_request_id;
    case OP_READDIR:
        return sftp->readdir_request_id;
    case OP_STAT:
        return sftp->stat_request_id;
    case OP_SETSTAT:
    case OP_READ:
    case OP_WRITE:
    case OP_UNLINK:
    case OP_MKDIR:
    case OP_RMDIR:
    case OP_RENAME:
    case OP_POSIX_RENAME:
    case OP_SYMLINK:
    case OP_FSYNC:
        /* these use sftp->request_id (assigned before the EAGAIN wait) */
        return sftp->request_id ? sftp->request_id - 1 : 0;
    case OP_CLOSE:
        return h ? h->close_request_id : sftp->request_id - 1;
    case OP_STATVFS:
        return sftp->statvfs_request_id;
    case OP_FSTATVFS:
        return sftp->fstatvfs_request_id;
    case OP_REALPATH:
    case OP_READLINK:
        return sftp->request_id ? sftp->request_id - 1 : 0;
    case OP_FSTAT:
        return sftp->fstat_request_id;
    default:
        return sftp->request_id;
    }
}

/* Run one client call to completion (bounded; everything returns EAGAIN
 * fast in nonblocking mode) */
static void op_drive(LIBSSH2_SFTP *sftp, LIBSSH2_SFTP_HANDLE **h, uint8_t op)
{
    char buf[512];
    char target[512];
    const char *path = "/f";
    const char *path2 = "/g";
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    LIBSSH2_SFTP_STATVFS st;
    int rc = 0;
    int tries;

    for(tries = 0; tries < 12; tries++) {
        switch(op) {
        case OP_OPEN:
            if(!*h)
                *h = libssh2_sftp_open(sftp, path, LIBSSH2_FXF_READ, 0);
            rc = *h ? 0 : sftp->channel->session->err_code;
            break;
        case OP_READDIR:
            if(*h)
                rc = (int)libssh2_sftp_readdir_ex(*h, buf, sizeof(buf),
                                                  NULL, 0, &attrs);
            break;
        case OP_STAT:
            rc = libssh2_sftp_stat(sftp, path, &attrs);
            break;
        case OP_SETSTAT:
            memset(&attrs, 0, sizeof(attrs));
            attrs.flags = LIBSSH2_SFTP_ATTR_PERMISSIONS;
            attrs.permissions = 0644;
            rc = libssh2_sftp_setstat(sftp, path, &attrs);
            break;
        case OP_READ:
            if(*h)
                rc = (int)libssh2_sftp_read(*h, buf, sizeof(buf));
            break;
        case OP_WRITE:
            if(*h)
                rc = (int)libssh2_sftp_write(*h, buf, 64);
            break;
        case OP_CLOSE:
            if(*h) {
                rc = libssh2_sftp_close(*h);
                if(rc == 0)
                    *h = NULL;
            }
            break;
        case OP_UNLINK:
            rc = libssh2_sftp_unlink(sftp, path);
            break;
        case OP_MKDIR:
            rc = libssh2_sftp_mkdir(sftp, path, 0755);
            break;
        case OP_RMDIR:
            rc = libssh2_sftp_rmdir(sftp, path);
            break;
        case OP_RENAME:
            rc = libssh2_sftp_rename_ex(sftp, path, (unsigned int)strlen(path),
                                        path2, (unsigned int)strlen(path2),
                                        LIBSSH2_SFTP_RENAME_OVERWRITE |
                                        LIBSSH2_SFTP_RENAME_ATOMIC |
                                        LIBSSH2_SFTP_RENAME_NATIVE);
            break;
        case OP_POSIX_RENAME:
            rc = libssh2_sftp_posix_rename(sftp, path, path2);
            break;
        case OP_SYMLINK:
            rc = (int)libssh2_sftp_symlink_ex(sftp, path,
                                              (unsigned int)strlen(path),
                                              target, sizeof(target),
                                              LIBSSH2_SFTP_SYMLINK);
            break;
        case OP_STATVFS:
            rc = libssh2_sftp_statvfs(sftp, path, strlen(path), &st);
            break;
        case OP_FSTATVFS:
            if(*h)
                rc = libssh2_sftp_fstatvfs(*h, &st);
            break;
        case OP_FSYNC:
            if(*h)
                rc = libssh2_sftp_fsync(*h);
            break;
        case OP_REALPATH:
            rc = (int)libssh2_sftp_symlink_ex(sftp, path,
                                              (unsigned int)strlen(path),
                                              target, sizeof(target),
                                              LIBSSH2_SFTP_REALPATH);
            break;
        case OP_READLINK:
            rc = (int)libssh2_sftp_symlink_ex(sftp, path,
                                              (unsigned int)strlen(path),
                                              target, sizeof(target),
                                              LIBSSH2_SFTP_READLINK);
            break;
        case OP_FSTAT:
            if(*h)
                rc = libssh2_sftp_fstat(*h, &attrs);
            break;
        default:
            return;
        }

        if(rc != (int)LIBSSH2_ERROR_EAGAIN)
            return;
    }
}

/* Expected FXP reply type per op (0 in the record means "use this") */
static uint8_t op_reply_type(uint8_t op)
{
    switch(op) {
    case OP_OPEN:
        return SSH_FXP_HANDLE;
    case OP_READDIR:
    case OP_SYMLINK:
    case OP_REALPATH:
    case OP_READLINK:
        return SSH_FXP_NAME;
    case OP_STAT:
    case OP_SETSTAT:
    case OP_FSTAT:
        return SSH_FXP_ATTRS;
    case OP_READ:
        return SSH_FXP_DATA;
    case OP_STATVFS:
    case OP_FSTATVFS:
        return SSH_FXP_EXTENDED_REPLY;
    default:
        return SSH_FXP_STATUS;
    }
}

/* Input: a script of records
 *   [u8 op][u8 reply type or 0][u16 body length][body...]
 * The body is the SFTP reply payload after the message type and request id;
 * the harness frames it into an SSH_MSG_CHANNEL_DATA packet and drives the
 * matching client call in nonblocking mode. */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int rc;
    int socket_fds[2] = { -1, -1 };
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_SFTP *sftp = NULL;
    LIBSSH2_SFTP_HANDLE *handle = NULL;
    uint32_t local_id;
    size_t pos = 0;
    int records = 0;
    int tries;

    if(size < 4)
        return 0;

    rc = libssh2_init(0);

    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 0;
    }

    if(socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds))
        goto EXIT_LABEL;

    session = libssh2_session_init();

    if(!session)
        goto EXIT_LABEL;

    /* Nonblocking: every wait surfaces as EAGAIN instead of blocking on
     * the scripted (possibly silent) peer. libssh2's blocking mode is
     * API-level only, so the socket descriptor itself must also be made
     * nonblocking: a blocking recv() on the silent peer would hang the
     * fuzzer until the timeout. */
    libssh2_session_set_blocking(session, 0);
    session->socket_fd = socket_fds[0];
    fcntl(socket_fds[0], F_SETFL,
          fcntl(socket_fds[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(socket_fds[1], F_SETFL,
          fcntl(socket_fds[1], F_GETFL, 0) | O_NONBLOCK);

    /* The SFTP API requires an authenticated session; this harness exercises
     * the server-reply parsers, so fake the post-auth state directly. */
    session->state |= SSH2_STATE_AUTHENTICATED;

    /* Kick off the SFTP subsystem: sends the channel open request. */
    (void)libssh2_sftp_init(session);

    if(!ssh2_list_first(&session->channels))
        goto EXIT_LABEL;

    if(!sftp_bootstrap(session, socket_fds[1], &sftp))
        goto EXIT_LABEL;

    local_id = ((LIBSSH2_CHANNEL *)ssh2_list_first(
                    &session->channels))->local.id;

    /* Drive the scripted operations. */
    while(pos + 4 <= size && records < 32) {
        uint8_t op = data[pos];
        uint8_t type = data[pos + 1];
        uint16_t body_len = get16(data + pos + 2);
        const uint8_t *body;

        if(body_len > 1024)
            body_len = 1024;

        if(pos + 4 + body_len > size)
            body_len = (uint16_t)(size - pos - 4);

        if(op < OP_OPEN || op > OP_FSTAT)
            break;

        body = data + pos + 4;
        pos += 4 + body_len;
        records++;

        if(!type)
            type = op_reply_type(op);

        sftp_deliver(socket_fds[1], local_id, type,
                     op_request_id(sftp, handle, op), body, body_len);
        op_drive(sftp, &handle, op);
    }

    /* Teardown: answer the channel close so sftp_shutdown can complete. */
    {
        unsigned char cc[9];

        cc[0] = MSG_CHANNEL_CLOSE;
        cc[1] = (unsigned char)(local_id >> 24);
        cc[2] = (unsigned char)(local_id >> 16);
        cc[3] = (unsigned char)(local_id >> 8);
        cc[4] = (unsigned char)local_id;
        cc[5] = 0;
        cc[6] = 0;
        cc[7] = 0;
        cc[8] = 7;
        ssh_send(socket_fds[1], cc, sizeof(cc));
    }

    for(tries = 0; tries < 16 && sftp; tries++) {
        rc = libssh2_sftp_shutdown(sftp);

        if(rc != (int)LIBSSH2_ERROR_EAGAIN)
            break;
    }

EXIT_LABEL:

    if(session)
        libssh2_session_free(session);

    if(socket_fds[0] != -1)
        close(socket_fds[0]);

    if(socket_fds[1] != -1)
        close(socket_fds[1]);

    return 0;
}



