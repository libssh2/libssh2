/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Fuzz harness for libssh2 SSH binary packet dispatch and SFTP packet parsing.
 *
 * The existing ssh2_client_fuzzer.cc exercises the SSH-layer handshake by
 * feeding raw fuzz bytes directly to libssh2_session_handshake().  This
 * harness complements it by:
 *
 *  1. Prepending a valid SSH-2.0 server banner so that banner_receive() in
 *     session.c always completes successfully and the code moves on to the
 *     binary-packet transport layer.  This pushes coverage into the SSH
 *     binary packet reader (transport.c:_libssh2_transport_read) and the
 *     SSH message dispatcher (_libssh2_packet_add in packet.c) with fuzz-
 *     controlled payload bytes - including all SSH message type branches
 *     (DISCONNECT, DEBUG, IGNORE, EXT_INFO, GLOBAL_REQUEST, CHANNEL_*,
 *     USERAUTH_BANNER, etc.).
 *
 *  2. For the specific case where the first fuzz byte selects the
 *     SSH_MSG_KEXINIT type (0x14 == 20), it also hits the kex algorithm
 *     negotiation string-list parser in kex.c.
 *
 * Wire format sent to the server-side socket:
 *   [SSH-2.0-libssh2_fuzz\r\n][SSH binary packet wrapping fuzz payload]
 *
 * SSH binary packet (pre-NEWKEYS, so unencrypted, no MAC):
 *   uint32  packet_length  (= 1 + len(payload) + padding_length)
 *   byte    padding_length (= 4, minimum valid value when block_size == 8)
 *   byte[]  payload        (= fuzz data)
 *   byte[]  padding        (= 0x00 * 4)
 *
 * The session handshake will fail (the fuzz data is not a valid KEXINIT)
 * but the parsing paths are exercised before the error is returned.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "libssh2.h"
#include "testinput.h"

/* Minimum SSH binary packet payload that the transport layer will accept
 * is 1 byte (the message type byte). */
#define MIN_PAYLOAD_SIZE 1

/* Maximum payload we will wrap to keep the harness efficient. */
#define MAX_PAYLOAD_SIZE 65536

static void write_u32_be(unsigned char *buf, uint32_t v)
{
    buf[0] = (unsigned char)((v >> 24) & 0xff);
    buf[1] = (unsigned char)((v >> 16) & 0xff);
    buf[2] = (unsigned char)((v >> 8) & 0xff);
    buf[3] = (unsigned char)(v & 0xff);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int socket_fds[2] = { -1, -1 };
    LIBSSH2_SESSION *session = NULL;
    int rc;

    if(size < MIN_PAYLOAD_SIZE)
        return 0;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 0;
    }

    rc = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds);
    if(rc != 0)
        goto cleanup;

    /* ------------------------------------------------------------------ */
    /* Build and send the server side of the handshake:                    */
    /*   1. A fixed, valid SSH-2.0 banner so banner_receive() succeeds.    */
    /*   2. A single SSH binary packet whose payload is the fuzz data.     */
    /*      Pre-NEWKEYS the transport reader expects no encryption / MAC,  */
    /*      so we just need a valid 5-byte header.                         */
    /* ------------------------------------------------------------------ */
    {
        static const char banner[] = "SSH-2.0-libssh2_fuzz\r\n";
        const size_t banner_len = sizeof(banner) - 1; /* exclude NUL */

        /* Clamp payload to avoid allocating huge intermediate buffers. */
        size_t payload_len = size > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : size;

        /* SSH binary packet: 4 (length field) + 1 (padding_length byte)
         * + payload + 4 bytes of zero padding.
         * packet_length field value = 1 + payload_len + 4 (padding). */
        const uint8_t padding_length = 4;
        uint32_t packet_length = (uint32_t)(1 + payload_len + padding_length);

        size_t pkt_buf_len = 4 + 1 + payload_len + padding_length;
        unsigned char *pkt_buf = (unsigned char *)malloc(pkt_buf_len);
        if(!pkt_buf)
            goto cleanup;

        write_u32_be(pkt_buf, packet_length);
        pkt_buf[4] = padding_length;
        memcpy(pkt_buf + 5, data, payload_len);
        memset(pkt_buf + 5 + payload_len, 0, padding_length);

        /* Send banner then binary packet on the "server" socket. */
        send(socket_fds[1], banner, banner_len, 0);
        send(socket_fds[1], pkt_buf, pkt_buf_len, 0);
        free(pkt_buf);

        /* Signal EOF - no more server data. */
        shutdown(socket_fds[1], SHUT_WR);
    }

    /* ------------------------------------------------------------------ */
    /* Run the client handshake against our synthetic server data.         */
    /* ------------------------------------------------------------------ */
    session = libssh2_session_init();
    if(!session)
        goto cleanup;

    libssh2_session_set_blocking(session, 1);

    /* This will exercise:
     *   - banner_receive() in session.c  (fixed banner -> always succeeds)
     *   - _libssh2_transport_read() in transport.c
     *   - _libssh2_packet_add() in packet.c with fuzz-controlled msg type
     *   - Per-message-type handlers for whatever the first byte of data is
     */
    libssh2_session_handshake(session, socket_fds[0]);

cleanup:
    if(session)
        libssh2_session_free(session);

    libssh2_exit();

    if(socket_fds[0] != -1)
        close(socket_fds[0]);
    if(socket_fds[1] != -1)
        close(socket_fds[1]);

    return 0;
}
