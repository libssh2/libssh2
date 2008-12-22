/* Copyright (c) 2004-2008, Sara Golemon <sarag@libssh2.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 *   Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials
 *   provided with the distribution.
 *
 *   Neither the name of the copyright holder nor the names
 *   of any other contributors may be used to endorse or
 *   promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include "libssh2_priv.h"
#include "libssh2_sftp.h"

/* Note: Version 6 was documented at the time of writing
 * However it was marked as "DO NOT IMPLEMENT" due to pending changes
 *
 * This release of libssh2 implements Version 5 with automatic downgrade
 * based on server's declaration
 */

/* SFTP packet types */
#define SSH_FXP_INIT                            1
#define SSH_FXP_VERSION                         2
#define SSH_FXP_OPEN                            3
#define SSH_FXP_CLOSE                           4
#define SSH_FXP_READ                            5
#define SSH_FXP_WRITE                           6
#define SSH_FXP_LSTAT                           7
#define SSH_FXP_FSTAT                           8
#define SSH_FXP_SETSTAT                         9
#define SSH_FXP_FSETSTAT                        10
#define SSH_FXP_OPENDIR                         11
#define SSH_FXP_READDIR                         12
#define SSH_FXP_REMOVE                          13
#define SSH_FXP_MKDIR                           14
#define SSH_FXP_RMDIR                           15
#define SSH_FXP_REALPATH                        16
#define SSH_FXP_STAT                            17
#define SSH_FXP_RENAME                          18
#define SSH_FXP_READLINK                        19
#define SSH_FXP_SYMLINK                         20
#define SSH_FXP_STATUS                          101
#define SSH_FXP_HANDLE                          102
#define SSH_FXP_DATA                            103
#define SSH_FXP_NAME                            104
#define SSH_FXP_ATTRS                           105
#define SSH_FXP_EXTENDED                        200
#define SSH_FXP_EXTENDED_REPLY                  201

#define LIBSSH2_SFTP_HANDLE_FILE        0
#define LIBSSH2_SFTP_HANDLE_DIR         1

/* S_IFREG */
#define LIBSSH2_SFTP_ATTR_PFILETYPE_FILE        0100000
/* S_IFDIR */
#define LIBSSH2_SFTP_ATTR_PFILETYPE_DIR         0040000

/* {{{ sftp_packet_add
 * Add a packet to the SFTP packet brigade
 */
static int
sftp_packet_add(LIBSSH2_SFTP * sftp, unsigned char *data,
                unsigned long data_len)
{
    LIBSSH2_SESSION *session = sftp->channel->session;
    LIBSSH2_PACKET *packet;

    _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Received packet %d (len %d)",
                   (int) data[0], data_len);
    packet = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_PACKET));
    if (!packet) {
        libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                      "Unable to allocate datablock for SFTP packet", 0);
        return -1;
    }
    memset(packet, 0, sizeof(LIBSSH2_PACKET));

    packet->data = data;
    packet->data_len = data_len;
    packet->data_head = 5;
    packet->brigade = &sftp->packets;
    packet->next = NULL;
    packet->prev = sftp->packets.tail;
    if (packet->prev) {
        packet->prev->next = packet;
    } else {
        sftp->packets.head = packet;
    }
    sftp->packets.tail = packet;

    return 0;
}

/* }}} */

/* {{{ sftp_packet_read
 * Frame an SFTP packet off the channel
 */
static int
sftp_packet_read(LIBSSH2_SFTP * sftp)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned char buffer[4];    /* To store the packet length */
    unsigned char *packet;
    unsigned long packet_len, packet_received;
    ssize_t bytes_received;
    int rc;

    _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Waiting for packet");


    /* If there was a previous partial, start using it */
    if (sftp->partial_packet) {

        packet = sftp->partial_packet;
        packet_len = sftp->partial_len;
        packet_received = sftp->partial_received;
        sftp->partial_packet = NULL;

        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "partial read cont, len: %lu", packet_len);
    }
    else {
        rc = libssh2_channel_read_ex(channel, 0, (char *) buffer, 4);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
        else if (4 != rc) {
            /* TODO: this is stupid since we can in fact get 1-3 bytes in a
               legitimate working case as well if the connection happens to be
               super slow or something */
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                          "Timeout waiting for FXP packet", 0);
            return -1;
        }

        packet_len = libssh2_ntohu32(buffer);
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Data begin - Packet Length: %lu", packet_len);
        if (packet_len > LIBSSH2_SFTP_PACKET_MAXLEN) {
            libssh2_error(session, LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED,
                          "SFTP packet too large", 0);
            return -1;
        }

        packet = LIBSSH2_ALLOC(session, packet_len);
        if (!packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate SFTP packet", 0);
            return -1;
        }

        packet_received = 0;
    }

    /* Read as much of the packet as we can */
    while (packet_len > packet_received) {
        bytes_received =
            libssh2_channel_read_ex(channel, 0,
                                    (char *) packet + packet_received,
                                    packet_len - packet_received);

        if (bytes_received == PACKET_EAGAIN) {
            /*
             * We received EAGAIN, save what we have and
             * return to EAGAIN to the caller
             */
            sftp->partial_packet = packet;
            sftp->partial_len = packet_len;
            sftp->partial_received = packet_received;
            packet = NULL;

            return PACKET_EAGAIN;
        }
        else if (bytes_received < 0) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                          "Receive error waiting for SFTP packet", 0);
            LIBSSH2_FREE(session, packet);
            return -1;
        }
        packet_received += bytes_received;
    }

    if (sftp_packet_add(sftp, packet, packet_len)) {
        LIBSSH2_FREE(session, packet);
        return -1;
    }

    return packet[0];
}

/* }}} */

/* {{{ sftp_packet_ask
 * A la libssh2_packet_ask()
 */
static int
sftp_packet_ask(LIBSSH2_SFTP * sftp, unsigned char packet_type,
                unsigned long request_id, unsigned char **data,
                unsigned long *data_len, int poll_channel)
{
    LIBSSH2_SESSION *session = sftp->channel->session;
    LIBSSH2_PACKET *packet = sftp->packets.head;
    unsigned char match_buf[5];
    int match_len = 5;

    _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Asking for %d packet",
                   (int) packet_type);
    if (poll_channel) {
        int ret = sftp_packet_read(sftp);
        if (ret == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (ret < 0) {
            return -1;
        }
    }

    match_buf[0] = packet_type;
    if (packet_type == SSH_FXP_VERSION) {
        /* Special consideration when matching VERSION packet */
        match_len = 1;
    } else {
        libssh2_htonu32(match_buf + 1, request_id);
    }

    while (packet) {
        if (strncmp((char *) packet->data, (char *) match_buf, match_len) == 0) {
            *data = packet->data;
            *data_len = packet->data_len;

            if (packet->prev) {
                packet->prev->next = packet->next;
            } else {
                sftp->packets.head = packet->next;
            }

            if (packet->next) {
                packet->next->prev = packet->prev;
            } else {
                sftp->packets.tail = packet->prev;
            }

            LIBSSH2_FREE(session, packet);

            return 0;
        }
        packet = packet->next;
    }
    return -1;
}

/* }}} */

/* {{{ sftp_packet_require
 * A la libssh2_packet_require
 */
static int
sftp_packet_require(LIBSSH2_SFTP * sftp, unsigned char packet_type,
                    unsigned long request_id, unsigned char **data,
                    unsigned long *data_len)
{
    LIBSSH2_SESSION *session = sftp->channel->session;
    int ret;

    _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Requiring %d packet",
                   (int) packet_type);

    if (sftp_packet_ask(sftp, packet_type, request_id, data,
                        data_len, 0) == 0) {
        /* The right packet was available in the packet brigade */
        return 0;
    }

    while (session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
        ret = sftp_packet_read(sftp);
        if (ret == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (ret <= 0) {
            return -1;
        }

        if (packet_type == ret) {
            /* Be lazy, let packet_ask pull it out of the brigade */
            return sftp_packet_ask(sftp, packet_type, request_id, data,
                                   data_len, 0);
        }
    }

    /* Only reached if the socket died */
    return -1;
}

/* }}} */

/* {{{ sftp_packet_requirev
 * Require one of N possible reponses
 */
static int
sftp_packet_requirev(LIBSSH2_SFTP * sftp, int num_valid_responses,
                     const unsigned char *valid_responses,
                     unsigned long request_id, unsigned char **data,
                     unsigned long *data_len)
{
    int i;
    int ret;

    /* If no timeout is active, start a new one */
    if (sftp->requirev_start == 0) {
        sftp->requirev_start = time(NULL);
    }

    while (sftp->channel->session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
        for(i = 0; i < num_valid_responses; i++) {
            if (sftp_packet_ask(sftp, valid_responses[i], request_id,
                                data, data_len, 0) == 0) {
                /*
                 * Set to zero before all returns to say
                 * the timeout is not active
                 */
                sftp->requirev_start = 0;
                return 0;
            }
        }

        ret = sftp_packet_read(sftp);
        if ((ret < 0) && (ret != PACKET_EAGAIN)) {
            sftp->requirev_start = 0;
            return -1;
        } else if (ret <= 0) {
            /* prevent busy-looping */
            long left =
                LIBSSH2_READ_TIMEOUT - (time(NULL) - sftp->requirev_start);

            if (left <= 0) {
                sftp->requirev_start = 0;
                return PACKET_TIMEOUT;
            } else if (sftp->channel->session->socket_block
                       && (libssh2_waitsocket(sftp->channel->session, left) <=
                           0)) {
                sftp->requirev_start = 0;
                return PACKET_TIMEOUT;
            } else if (ret == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            }
        }
    }

    sftp->requirev_start = 0;
    return -1;
}

/* }}} */

/* {{{ libssh2_sftp_attrsize
 * Size that attr will occupy when turned into a bin struct
 */
static int
libssh2_sftp_attrsize(const LIBSSH2_SFTP_ATTRIBUTES * attrs)
{
    int attrsize = 4;           /* flags(4) */

    if (!attrs) {
        return attrsize;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE)
        attrsize += 8;
    if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID)
        attrsize += 8;
    if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)
        attrsize += 4;
    if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME)
        attrsize += 8;          /* atime + mtime as u32 */

    return attrsize;
}

/* }}} */

/* {{{ libssh2_sftp_attr2bin
 * Populate attributes into an SFTP block
 */
static int
libssh2_sftp_attr2bin(unsigned char *p, const LIBSSH2_SFTP_ATTRIBUTES * attrs)
{
    unsigned char *s = p;
    unsigned long flag_mask =
        LIBSSH2_SFTP_ATTR_SIZE | LIBSSH2_SFTP_ATTR_UIDGID |
        LIBSSH2_SFTP_ATTR_PERMISSIONS | LIBSSH2_SFTP_ATTR_ACMODTIME;

    /* TODO: When we add SFTP4+ functionality flag_mask can get additional bits */

    if (!attrs) {
        libssh2_htonu32(s, 0);
        return 4;
    }

    libssh2_htonu32(s, attrs->flags & flag_mask);
    s += 4;

    if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) {
        libssh2_htonu64(s, attrs->filesize);
        s += 8;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) {
        libssh2_htonu32(s, attrs->uid);
        s += 4;
        libssh2_htonu32(s, attrs->gid);
        s += 4;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        libssh2_htonu32(s, attrs->permissions);
        s += 4;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
        libssh2_htonu32(s, attrs->atime);
        s += 4;
        libssh2_htonu32(s, attrs->mtime);
        s += 4;
    }

    return (s - p);
}

/* }}} */

/* {{{ libssh2_sftp_bin2attr
 */
static int
libssh2_sftp_bin2attr(LIBSSH2_SFTP_ATTRIBUTES * attrs, const unsigned char *p)
{
    const unsigned char *s = p;

    memset(attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
    attrs->flags = libssh2_ntohu32(s);
    s += 4;

    if (attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) {
        attrs->filesize = libssh2_ntohu64(s);
        s += 8;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) {
        attrs->uid = libssh2_ntohu32(s);
        s += 4;
        attrs->gid = libssh2_ntohu32(s);
        s += 4;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        attrs->permissions = libssh2_ntohu32(s);
        s += 4;
    }

    if (attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
        attrs->atime = libssh2_ntohu32(s);
        s += 4;
        attrs->mtime = libssh2_ntohu32(s);
        s += 4;
    }

    return (s - p);
}

/* }}} */

/* ************
   * SFTP API *
   ************ */

LIBSSH2_CHANNEL_CLOSE_FUNC(libssh2_sftp_dtor);

/* {{{ libssh2_sftp_dtor
 * Shutdown an SFTP stream when the channel closes
 */
LIBSSH2_CHANNEL_CLOSE_FUNC(libssh2_sftp_dtor)
{
    LIBSSH2_SFTP *sftp = (LIBSSH2_SFTP *) (*channel_abstract);

    (void) session_abstract;
    (void) channel;

    /* Loop through handles closing them */
    while (sftp->handles) {
        libssh2_sftp_close_handle(sftp->handles);
    }

    /* Free the partial packet storage for sftp_packet_read */
    if (sftp->partial_packet) {
        LIBSSH2_FREE(session, sftp->partial_packet);
    }

    /* Free the packet storage for _libssh2_sftp_packet_readdir */
    if (sftp->readdir_packet) {
        LIBSSH2_FREE(session, sftp->readdir_packet);
    }

    LIBSSH2_FREE(session, sftp);
}

/* }}} */

/* {{{ libssh2_sftp_init
 * Startup an SFTP session
 *
 * NOTE:  Will block in a busy loop on error.  This has to be done,
 *        otherwise the blocking error code would erase the true
 *        cause of the error.
 */
LIBSSH2_API LIBSSH2_SFTP *
libssh2_sftp_init(LIBSSH2_SESSION * session)
{
    unsigned char *data, *s;
    unsigned long data_len;
    int rc;

    if (session->sftpInit_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Initializing SFTP subsystem");

        session->sftpInit_sftp = NULL;

        session->sftpInit_state = libssh2_NB_state_created;
    }

    if (session->sftpInit_state == libssh2_NB_state_created) {
        session->sftpInit_channel =
            libssh2_channel_open_ex(session, "session", sizeof("session") - 1,
                                    LIBSSH2_CHANNEL_WINDOW_DEFAULT,
                                    LIBSSH2_CHANNEL_PACKET_DEFAULT, NULL, 0);
        if (!session->sftpInit_channel) {
            if (libssh2_session_last_errno(session) == LIBSSH2_ERROR_EAGAIN) {
                libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                              "Would block starting up channel", 0);
                return NULL;
            } else if (libssh2_session_last_errno(session) !=
                       LIBSSH2_ERROR_EAGAIN) {
                libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE,
                              "Unable to startup channel", 0);
                session->sftpInit_state = libssh2_NB_state_idle;
                return NULL;
            }
        }

        session->sftpInit_state = libssh2_NB_state_sent;
    }

    if (session->sftpInit_state == libssh2_NB_state_sent) {
        rc = libssh2_channel_process_startup(session->sftpInit_channel,
                                             "subsystem",
                                             sizeof("subsystem") - 1, "sftp",
                                             strlen("sftp"));
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block to request SFTP subsystem", 0);
            return NULL;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE,
                          "Unable to request SFTP subsystem", 0);
            goto sftp_init_error;
        }

        session->sftpInit_state = libssh2_NB_state_sent1;
    }

    if (session->sftpInit_state == libssh2_NB_state_sent1) {
        rc = libssh2_channel_handle_extended_data2(session->sftpInit_channel,
                                                   LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE);
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block requesting handle extended data", 0);
            return NULL;
        }

        session->sftpInit_sftp = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_SFTP));
        if (!session->sftpInit_sftp) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate a new SFTP structure", 0);
            goto sftp_init_error;
        }
        memset(session->sftpInit_sftp, 0, sizeof(LIBSSH2_SFTP));
        session->sftpInit_sftp->channel = session->sftpInit_channel;
        session->sftpInit_sftp->request_id = 0;

        libssh2_htonu32(session->sftpInit_buffer, 5);
        session->sftpInit_buffer[4] = SSH_FXP_INIT;
        libssh2_htonu32(session->sftpInit_buffer + 5, LIBSSH2_SFTP_VERSION);

        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Sending FXP_INIT packet advertising version %d support",
                       (int) LIBSSH2_SFTP_VERSION);

        session->sftpInit_state = libssh2_NB_state_sent2;
    }

    if (session->sftpInit_state == libssh2_NB_state_sent2) {
        rc = libssh2_channel_write_ex(session->sftpInit_channel, 0,
                                      (char *) session->sftpInit_buffer, 9);
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block sending SSH_FXP_INIT", 0);
            return NULL;
        } else if (9 != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SSH_FXP_INIT", 0);
            goto sftp_init_error;
        }

        session->sftpInit_state = libssh2_NB_state_sent3;
    }

    /* For initiallization we are requiring blocking, probably reasonable */
    rc = sftp_packet_require(session->sftpInit_sftp, SSH_FXP_VERSION,
                             0, &data, &data_len);
    if (rc == PACKET_EAGAIN) {
        libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                      "Would block waiting for response from SFTP subsystem",
                      0);
        return NULL;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for response from SFTP subsystem", 0);
        goto sftp_init_error;
    }
    if (data_len < 5) {
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "Invalid SSH_FXP_VERSION response", 0);
        goto sftp_init_error;
    }

    s = data + 1;
    session->sftpInit_sftp->version = libssh2_ntohu32(s);
    s += 4;
    if (session->sftpInit_sftp->version > LIBSSH2_SFTP_VERSION) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Truncating remote SFTP version from %lu",
                       session->sftpInit_sftp->version);
        session->sftpInit_sftp->version = LIBSSH2_SFTP_VERSION;
    }
    _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                   "Enabling SFTP version %lu compatability",
                   session->sftpInit_sftp->version);
    while (s < (data + data_len)) {
        unsigned char *extension_name, *extension_data;
        unsigned long extname_len, extdata_len;

        extname_len = libssh2_ntohu32(s);
        s += 4;
        extension_name = s;
        s += extname_len;

        extdata_len = libssh2_ntohu32(s);
        s += 4;
        extension_data = s;
        s += extdata_len;

        /* TODO: Actually process extensions */
    }
    LIBSSH2_FREE(session, data);

    /* Make sure that when the channel gets closed, the SFTP service is shut down too */
    session->sftpInit_sftp->channel->abstract = session->sftpInit_sftp;
    session->sftpInit_sftp->channel->close_cb = libssh2_sftp_dtor;

    session->sftpInit_state = libssh2_NB_state_idle;
    return session->sftpInit_sftp;

  sftp_init_error:
    while (libssh2_channel_free(session->sftpInit_channel) == PACKET_EAGAIN);
    session->sftpInit_channel = NULL;
    if (session->sftpInit_sftp) {
        LIBSSH2_FREE(session, session->sftpInit_sftp);
        session->sftpInit_sftp = NULL;
    }
    session->sftpInit_state = libssh2_NB_state_idle;
    return NULL;
}

/* }}} */

/* {{{ libssh2_sftp_shutdown
 * Shutsdown the SFTP subsystem
 */
LIBSSH2_API int
libssh2_sftp_shutdown(LIBSSH2_SFTP * sftp)
{
    /*
     * Make sure all memory used in the state variables are free
     */
    if (sftp->partial_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->partial_packet);
        sftp->partial_packet = NULL;
    }
    if (sftp->open_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->open_packet);
        sftp->open_packet = NULL;
    }
    if (sftp->readdir_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->readdir_packet);
        sftp->readdir_packet = NULL;
    }
    if (sftp->write_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->write_packet);
        sftp->write_packet = NULL;
    }
    if (sftp->fstat_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->fstat_packet);
        sftp->fstat_packet = NULL;
    }
    if (sftp->unlink_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->unlink_packet);
        sftp->unlink_packet = NULL;
    }
    if (sftp->rename_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->rename_packet);
        sftp->rename_packet = NULL;
    }
    if (sftp->mkdir_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->mkdir_packet);
        sftp->mkdir_packet = NULL;
    }
    if (sftp->rmdir_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->rmdir_packet);
        sftp->rmdir_packet = NULL;
    }
    if (sftp->stat_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->stat_packet);
        sftp->stat_packet = NULL;
    }
    if (sftp->symlink_packet) {
        LIBSSH2_FREE(sftp->channel->session, sftp->symlink_packet);
        sftp->symlink_packet = NULL;
    }

    return libssh2_channel_free(sftp->channel);
}

/* }}} */

/* *******************************
   * SFTP File and Directory Ops *
   ******************************* */

/* {{{ libssh2_sftp_open_ex
 */
LIBSSH2_API LIBSSH2_SFTP_HANDLE *
libssh2_sftp_open_ex(LIBSSH2_SFTP * sftp, const char *filename,
                     unsigned int filename_len, unsigned long flags, long mode,
                     int open_type)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    LIBSSH2_SFTP_HANDLE *fp;
    LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    unsigned long data_len;
    unsigned char *data, *s;
    static const unsigned char fopen_responses[2] =
        { SSH_FXP_HANDLE, SSH_FXP_STATUS };
    int rc;

    if (sftp->open_state == libssh2_NB_state_idle) {
        /* packet_len(4) + packet_type(1) + request_id(4) + filename_len(4) +
           flags(4) */
        sftp->open_packet_len = filename_len + 13 +
            ((open_type ==
              LIBSSH2_SFTP_OPENFILE) ? (4 +
                                        libssh2_sftp_attrsize(&attrs)) : 0);

        s = sftp->open_packet = LIBSSH2_ALLOC(session, sftp->open_packet_len);
        if (!sftp->open_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_OPEN or "
                          "FXP_OPENDIR packet",
                          0);
            return NULL;
        }
        /* Filetype in SFTP 3 and earlier */
        attrs.permissions = mode |
            ((open_type ==
              LIBSSH2_SFTP_OPENFILE) ? LIBSSH2_SFTP_ATTR_PFILETYPE_FILE :
             LIBSSH2_SFTP_ATTR_PFILETYPE_DIR);

        libssh2_htonu32(s, sftp->open_packet_len - 4);
        s += 4;
        *(s++) =
            (open_type ==
             LIBSSH2_SFTP_OPENFILE) ? SSH_FXP_OPEN : SSH_FXP_OPENDIR;
        sftp->open_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->open_request_id);
        s += 4;
        libssh2_htonu32(s, filename_len);
        s += 4;
        memcpy(s, filename, filename_len);
        s += filename_len;
        if (open_type == LIBSSH2_SFTP_OPENFILE) {
            libssh2_htonu32(s, flags);
            s += 4;
            s += libssh2_sftp_attr2bin(s, &attrs);
        }

        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Sending %s open request",
                       (open_type ==
                        LIBSSH2_SFTP_OPENFILE) ? "file" : "directory");

        sftp->open_state = libssh2_NB_state_created;
    }

    if (sftp->open_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) sftp->open_packet,
                                      sftp->open_packet_len);
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block sending FXP_OPEN or FXP_OPENDIR command",
                          0);
            return NULL;
        }
        else if (sftp->open_packet_len != rc) {
            /* TODO: partial writes should be fine too and is not a sign of
               an error when in non-blocking mode! */

            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_OPEN or FXP_OPENDIR command", 0);
            LIBSSH2_FREE(session, sftp->open_packet);
            sftp->open_packet = NULL;
            sftp->open_state = libssh2_NB_state_idle;
            return NULL;
        }
        LIBSSH2_FREE(session, sftp->open_packet);
        sftp->open_packet = NULL;

        sftp->open_state = libssh2_NB_state_sent;
    }

    if (sftp->open_state == libssh2_NB_state_sent) {
        rc = sftp_packet_requirev(sftp, 2, fopen_responses,
                                  sftp->open_request_id, &data,
                                  &data_len);
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block waiting for status message", 0);
            return NULL;
        }
        else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                          "Timeout waiting for status message", 0);
            sftp->open_state = libssh2_NB_state_idle;
            return NULL;
        }
    }

    sftp->open_state = libssh2_NB_state_idle;

    /* OPEN can basically get STATUS or HANDLE back, where HANDLE implies a
       fine response while STATUS means error. It seems though that at times
       we get an SSH_FX_OK back in a STATUS, followed the "real" HANDLE so
       we need to properly deal with that. */
    if (data[0] == SSH_FXP_STATUS) {
        int badness = 1;
        sftp->last_errno = libssh2_ntohu32(data + 5);

        if(LIBSSH2_FX_OK == sftp->last_errno) {
            _libssh2_debug(session, LIBSSH2_DBG_SFTP, "got HANDLE FXOK!");

            /* silly situation, but check for a HANDLE */
            rc = sftp_packet_require(sftp, SSH_FXP_HANDLE,
                                     sftp->open_request_id, &data, &data_len);
            if(rc == PACKET_EAGAIN) {
                /* go back to sent state and wait for something else */
                sftp->open_state = libssh2_NB_state_sent;
                return NULL;
            }
            else if(!rc)
                /* we got the handle so this is not a bad situation */
                badness = 0;
        }

        if(badness) {
            libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                          "Failed opening remote file", 0);
            _libssh2_debug(session, LIBSSH2_DBG_SFTP, "got FXP_STATUS %d",
                           sftp->last_errno);
            LIBSSH2_FREE(session, data);
            return NULL;
        }
    }

    fp = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_SFTP_HANDLE));
    if (!fp) {
        libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                      "Unable to allocate new SFTP handle structure", 0);
        LIBSSH2_FREE(session, data);
        return NULL;
    }
    memset(fp, 0, sizeof(LIBSSH2_SFTP_HANDLE));
    fp->handle_type =
        (open_type ==
         LIBSSH2_SFTP_OPENFILE) ? LIBSSH2_SFTP_HANDLE_FILE :
        LIBSSH2_SFTP_HANDLE_DIR;

    fp->handle_len = libssh2_ntohu32(data + 5);
    if (fp->handle_len > SFTP_HANDLE_MAXLEN) {
        /* SFTP doesn't allow handles longer than 256 characters */
        fp->handle_len = SFTP_HANDLE_MAXLEN;
    }

    memcpy(fp->handle, data + 9, fp->handle_len);
    LIBSSH2_FREE(session, data);

    /* Link the file and the sftp session together */
    fp->next = sftp->handles;
    if (fp->next) {
        fp->next->prev = fp;
    }
    fp->sftp = sftp;

    fp->u.file.offset = 0;

    _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Open command successful");
    return fp;
}

/* }}} */

/* {{{ libssh2_sftp_read
 * Read from an SFTP file handle
 */
LIBSSH2_API ssize_t
libssh2_sftp_read(LIBSSH2_SFTP_HANDLE * handle, char *buffer,
                  size_t buffer_maxlen)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, request_id = 0;
    /* 25 = packet_len(4) + packet_type(1) + request_id(4) + handle_len(4) +
       offset(8) + length(4) */
    ssize_t packet_len = handle->handle_len + 25;
    unsigned char *packet, *s, *data;
    static const unsigned char read_responses[2] =
        { SSH_FXP_DATA, SSH_FXP_STATUS };
    size_t bytes_read = 0;
    size_t bytes_requested = 0;
    size_t total_read = 0;
    int retcode;

    if (sftp->read_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Reading %lu bytes from SFTP handle",
                       (unsigned long) buffer_maxlen);
        packet = handle->request_packet;
        sftp->read_state = libssh2_NB_state_allocated;
    } else {
        packet = sftp->read_packet;
        request_id = sftp->read_request_id;
        total_read = sftp->read_total_read;
    }

    while (total_read < buffer_maxlen) {
        s = packet;
        /*
         * If buffer_maxlen bytes will be requested, server may return all
         * with one packet.  But libssh2 have packet length limit.
         * So we request data by pieces.
         */
        bytes_requested = buffer_maxlen - total_read;
        /* 10 = packet_type(1) + request_id(4) + data_length(4) +
           end_of_line_flag(1)

           10 is changed to 13 below simple because it seems there's a
           "GlobalScape" SFTP server that responds with a slightly too big
           buffer at times and we can apparently compensate for that by doing
           this trick.

           Further details on this issue:

           https://sourceforge.net/mailarchive/forum.php?thread_name=9c3275a90811261517v6c0b1da2u918cc1b8370abf83%40mail.gmail.com&forum_name=libssh2-devel

           http://forums.globalscape.com/tm.aspx?m=15249

        */
        if (bytes_requested > LIBSSH2_SFTP_PACKET_MAXLEN - 13) {
            bytes_requested = LIBSSH2_SFTP_PACKET_MAXLEN - 13;
        }
#ifdef LIBSSH2_DEBUG_SFTP
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Requesting %lu bytes from SFTP handle",
                       (unsigned long) bytes_requested);
#endif

        if (sftp->read_state == libssh2_NB_state_allocated) {
            libssh2_htonu32(s, packet_len - 4);
            s += 4;
            *(s++) = SSH_FXP_READ;
            request_id = sftp->request_id++;
            libssh2_htonu32(s, request_id);
            s += 4;
            libssh2_htonu32(s, handle->handle_len);
            s += 4;

            memcpy(s, handle->handle, handle->handle_len);
            s += handle->handle_len;

            libssh2_htonu64(s, handle->u.file.offset);
            s += 8;

            libssh2_htonu32(s, bytes_requested);
            s += 4;

            sftp->read_state = libssh2_NB_state_created;
        }

        if (sftp->read_state == libssh2_NB_state_created) {
            retcode =
                libssh2_channel_write_ex(channel, 0, (char *) packet,
                                         packet_len);
            if (retcode == PACKET_EAGAIN) {
                sftp->read_packet = packet;
                sftp->read_request_id = request_id;
                sftp->read_total_read = total_read;
                return PACKET_EAGAIN;
            } else if (packet_len != retcode) {
                /* TODO: a partial write is not a critical error when in
                   non-blocking mode! */
                libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                              "Unable to send FXP_READ command", 0);
                sftp->read_packet = NULL;
                sftp->read_state = libssh2_NB_state_idle;
                return -1;
            }
            sftp->read_packet = packet;
            sftp->read_request_id = request_id;
            sftp->read_total_read = total_read;
            sftp->read_state = libssh2_NB_state_sent;
        }

        if (sftp->read_state == libssh2_NB_state_sent) {
            retcode =
                sftp_packet_requirev(sftp, 2, read_responses,
                                     request_id, &data, &data_len);
            if (retcode == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            } else if (retcode) {
                libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                              "Timeout waiting for status message", 0);
                sftp->read_packet = NULL;
                sftp->read_state = libssh2_NB_state_idle;
                return -1;
            }

            sftp->read_state = libssh2_NB_state_sent1;
        }

        switch (data[0]) {
        case SSH_FXP_STATUS:
            retcode = libssh2_ntohu32(data + 5);
            LIBSSH2_FREE(session, data);
            sftp->read_packet = NULL;
            sftp->read_state = libssh2_NB_state_idle;

            if (retcode == LIBSSH2_FX_EOF) {
                return total_read;
            } else {
                sftp->last_errno = retcode;
                libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                              "SFTP Protocol Error", 0);
                return -1;
            }

        case SSH_FXP_DATA:
            bytes_read = libssh2_ntohu32(data + 5);
            if (bytes_read > (data_len - 9)) {
                sftp->read_packet = NULL;
                sftp->read_state = libssh2_NB_state_idle;
                return -1;
            }
#ifdef LIBSSH2_DEBUG_SFTP
            _libssh2_debug(session, LIBSSH2_DBG_SFTP, "%lu bytes returned",
                           (unsigned long) bytes_read);
#endif
            memcpy(buffer + total_read, data + 9, bytes_read);
            handle->u.file.offset += bytes_read;
            total_read += bytes_read;
            LIBSSH2_FREE(session, data);
            /*
             * Set the state back to allocated, so a new one will be
             * created to either request more data or get EOF
             */
            sftp->read_state = libssh2_NB_state_allocated;
        }
    }

    sftp->read_packet = NULL;
    sftp->read_state = libssh2_NB_state_idle;
    return total_read;
}

/* }}} */

/* {{{ libssh2_sftp_readdir
 * Read from an SFTP directory handle
 */
LIBSSH2_API int
libssh2_sftp_readdir_ex(LIBSSH2_SFTP_HANDLE * handle, char *buffer,
                        size_t buffer_maxlen, char *longentry,
                        size_t longentry_maxlen,
                        LIBSSH2_SFTP_ATTRIBUTES * attrs)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    LIBSSH2_SFTP_ATTRIBUTES attrs_dummy;
    unsigned long data_len, filename_len, longentry_len, num_names;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + handle_len(4) */
    ssize_t packet_len = handle->handle_len + 13;
    unsigned char *s, *data;
    unsigned char read_responses[2] = { SSH_FXP_NAME, SSH_FXP_STATUS };
    int retcode;

    if (sftp->readdir_state == libssh2_NB_state_idle) {
        if (handle->u.dir.names_left) {
            /*
             * A prior request returned more than one directory entry,
             * feed it back from the buffer
             */
            unsigned char *s = (unsigned char *) handle->u.dir.next_name;
            unsigned long real_filename_len = libssh2_ntohu32(s);

            filename_len = real_filename_len;
            s += 4;
            if (filename_len > buffer_maxlen) {
                filename_len = buffer_maxlen;
            }
            memcpy(buffer, s, filename_len);
            s += real_filename_len;

            /* The filename is not null terminated, make it so if possible */
            if (filename_len < buffer_maxlen) {
                buffer[filename_len] = '\0';
            }

            if ((longentry == NULL) || (longentry_maxlen == 0)) {
                /* Skip longname */
                s += 4 + libssh2_ntohu32(s);
            } else {
                unsigned long real_longentry_len = libssh2_ntohu32(s);

                longentry_len = real_longentry_len;
                s += 4;
                if (longentry_len > longentry_maxlen) {
                    longentry_len = longentry_maxlen;
                }
                memcpy(longentry, s, longentry_len);
                s += real_longentry_len;

                /* The longentry is not null terminated, make it so if possible */
                if (longentry_len < longentry_maxlen) {
                    longentry[longentry_len] = '\0';
                }
            }

            if (attrs) {
                memset(attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
            }
            s += libssh2_sftp_bin2attr(attrs ? attrs : &attrs_dummy, s);

            handle->u.dir.next_name = (char *) s;
            if ((--handle->u.dir.names_left) == 0) {
                LIBSSH2_FREE(session, handle->u.dir.names_packet);
            }

            _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                           "libssh2_sftp_readdir_ex() return %d",
                           filename_len);
            return filename_len;
        }

        /* Request another entry(entries?) */

        s = sftp->readdir_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->readdir_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_READDIR packet",
                          0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = SSH_FXP_READDIR;
        sftp->readdir_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->readdir_request_id);
        s += 4;
        libssh2_htonu32(s, handle->handle_len);
        s += 4;
        memcpy(s, handle->handle, handle->handle_len);
        s += handle->handle_len;

        sftp->readdir_state = libssh2_NB_state_created;
    }

    if (sftp->readdir_state == libssh2_NB_state_created) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Reading entries from directory handle");
        if ((retcode =
             libssh2_channel_write_ex(channel, 0,
                                      (char *) sftp->readdir_packet,
                                      packet_len)) == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != retcode) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_READ command", 0);
            LIBSSH2_FREE(session, sftp->readdir_packet);
            sftp->readdir_packet = NULL;
            sftp->readdir_state = libssh2_NB_state_idle;
            return -1;
        }

        LIBSSH2_FREE(session, sftp->readdir_packet);
        sftp->readdir_packet = NULL;

        sftp->readdir_state = libssh2_NB_state_sent;
    }

    retcode =
        sftp_packet_requirev(sftp, 2, read_responses,
                             sftp->readdir_request_id, &data,
                             &data_len);
    if (retcode == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (retcode) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->readdir_state = libssh2_NB_state_idle;
        return -1;
    }

    if (data[0] == SSH_FXP_STATUS) {
        retcode = libssh2_ntohu32(data + 5);
        LIBSSH2_FREE(session, data);
        if (retcode == LIBSSH2_FX_EOF) {
            sftp->readdir_state = libssh2_NB_state_idle;
            return 0;
        } else {
            sftp->last_errno = retcode;
            libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                          "SFTP Protocol Error", 0);
            sftp->readdir_state = libssh2_NB_state_idle;
            return -1;
        }
    }

    num_names = libssh2_ntohu32(data + 5);
    _libssh2_debug(session, LIBSSH2_DBG_SFTP, "%lu entries returned",
                   num_names);
    if (num_names <= 0) {
        LIBSSH2_FREE(session, data);
        sftp->readdir_state = libssh2_NB_state_idle;
        return (num_names == 0) ? 0 : -1;
    }

    if (num_names == 1) {
        unsigned long real_filename_len = libssh2_ntohu32(data + 9);

        filename_len = real_filename_len;
        if (filename_len > buffer_maxlen) {
            filename_len = buffer_maxlen;
        }
        memcpy(buffer, data + 13, filename_len);

        /* The filename is not null terminated, make it so if possible */
        if (filename_len < buffer_maxlen) {
            buffer[filename_len] = '\0';
        }

        if (attrs) {
            memset(attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
            libssh2_sftp_bin2attr(attrs, data + 13 + real_filename_len +
                                  (4 +
                                   libssh2_ntohu32(data + 13 +
                                                   real_filename_len)));
        }
        LIBSSH2_FREE(session, data);

        sftp->readdir_state = libssh2_NB_state_idle;
        return filename_len;
    }

    handle->u.dir.names_left = num_names;
    handle->u.dir.names_packet = data;
    handle->u.dir.next_name = (char *) data + 9;

    sftp->readdir_state = libssh2_NB_state_idle;

    /* Be lazy, just use the name popping mechanism from the start of the function */
    return libssh2_sftp_readdir_ex(handle, buffer, buffer_maxlen, longentry,
                                   longentry_maxlen, attrs);
}

/* }}} */

/* {{{ libssh2_sftp_write
 * Write data to a file handle
 */
LIBSSH2_API ssize_t
libssh2_sftp_write(LIBSSH2_SFTP_HANDLE * handle, const char *buffer,
                   size_t count)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, retcode;
    /* 25 = packet_len(4) + packet_type(1) + request_id(4) + handle_len(4) +
       offset(8) + count(4) */
    ssize_t packet_len = handle->handle_len + count + 25;
    unsigned char *s, *data;
    int rc;

    if (sftp->write_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Writing %lu bytes",
                       (unsigned long) count);
        s = sftp->write_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->write_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_WRITE packet", 0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = SSH_FXP_WRITE;
        sftp->write_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->write_request_id);
        s += 4;
        libssh2_htonu32(s, handle->handle_len);
        s += 4;
        memcpy(s, handle->handle, handle->handle_len);
        s += handle->handle_len;
        libssh2_htonu64(s, handle->u.file.offset);
        s += 8;
        libssh2_htonu32(s, count);
        s += 4;
        memcpy(s, buffer, count);
        s += count;

        sftp->write_state = libssh2_NB_state_created;
    }

    if (sftp->write_state == libssh2_NB_state_created) {
        if ((rc =
             libssh2_channel_write_ex(channel, 0, (char *) sftp->write_packet,
                                      packet_len)) == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
        if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_READ command", 0);
            LIBSSH2_FREE(session, sftp->write_packet);
            sftp->write_packet = NULL;
            sftp->write_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->write_packet);
        sftp->write_packet = NULL;
        sftp->write_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_require(sftp, SSH_FXP_STATUS,
                             sftp->write_request_id, &data, &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->write_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->write_state = libssh2_NB_state_idle;

    retcode = libssh2_ntohu32(data + 5);
    LIBSSH2_FREE(session, data);

    if (retcode == LIBSSH2_FX_OK) {
        handle->u.file.offset += count;
        return count;
    }
    libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL, "SFTP Protocol Error",
                  0);
    sftp->last_errno = retcode;

    return -1;
}

/* }}} */

/* {{{ libssh2_sftp_fstat_ex
 * Get or Set stat on a file
 */
LIBSSH2_API int
libssh2_sftp_fstat_ex(LIBSSH2_SFTP_HANDLE * handle,
                      LIBSSH2_SFTP_ATTRIBUTES * attrs, int setstat)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + handle_len(4) */
    ssize_t packet_len =
        handle->handle_len + 13 + (setstat ? libssh2_sftp_attrsize(attrs) : 0);
    unsigned char *s, *data;
    static const unsigned char fstat_responses[2] =
        { SSH_FXP_ATTRS, SSH_FXP_STATUS };
    int rc;

    if (sftp->fstat_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Issuing %s command",
                       setstat ? "set-stat" : "stat");
        s = sftp->fstat_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->fstat_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FSTAT/FSETSTAT packet",
                          0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = setstat ? SSH_FXP_FSETSTAT : SSH_FXP_FSTAT;
        sftp->fstat_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->fstat_request_id);
        s += 4;
        libssh2_htonu32(s, handle->handle_len);
        s += 4;
        memcpy(s, handle->handle, handle->handle_len);
        s += handle->handle_len;
        if (setstat) {
            s += libssh2_sftp_attr2bin(s, attrs);
        }

        sftp->fstat_state = libssh2_NB_state_created;
    }

    if (sftp->fstat_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) sftp->fstat_packet,
                                      packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          (setstat ? "Unable to send FXP_FSETSTAT"
                           : "Unable to send FXP_FSTAT command"), 0);
            LIBSSH2_FREE(session, sftp->fstat_packet);
            sftp->fstat_packet = NULL;
            sftp->fstat_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->fstat_packet);
        sftp->fstat_packet = NULL;

        sftp->fstat_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_requirev(sftp, 2, fstat_responses,
                              sftp->fstat_request_id, &data,
                              &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->fstat_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->fstat_state = libssh2_NB_state_idle;

    if (data[0] == SSH_FXP_STATUS) {
        int retcode;

        retcode = libssh2_ntohu32(data + 5);
        LIBSSH2_FREE(session, data);
        if (retcode == LIBSSH2_FX_OK) {
            return 0;
        } else {
            sftp->last_errno = retcode;
            libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                          "SFTP Protocol Error", 0);
            return -1;
        }
    }

    libssh2_sftp_bin2attr(attrs, data + 5);

    return 0;
}

/* }}} */

/* {{{ libssh2_sftp_seek
 * Set the read/write pointer to an arbitrary position within the file
 */
LIBSSH2_API void
libssh2_sftp_seek(LIBSSH2_SFTP_HANDLE * handle, size_t offset)
{
    handle->u.file.offset = offset;
}

/* }}} */

/* {{{ libssh2_sftp_seek64
 * Set the read/write pointer to an arbitrary position within the file
 */
LIBSSH2_API void
libssh2_sftp_seek64(LIBSSH2_SFTP_HANDLE * handle, libssh2_uint64_t offset)
{
    handle->u.file.offset = offset;
}

/* }}} */

/* {{{ libssh2_sftp_tell
 * Return the current read/write pointer's offset
 */
LIBSSH2_API size_t
libssh2_sftp_tell(LIBSSH2_SFTP_HANDLE * handle)
{
    return handle->u.file.offset;
}

/* {{{ libssh2_sftp_tell64
 * Return the current read/write pointer's offset
 */
LIBSSH2_API libssh2_uint64_t
libssh2_sftp_tell64(LIBSSH2_SFTP_HANDLE * handle)
{
    return handle->u.file.offset;
}

/* }}} */


/* {{{ libssh2_sftp_close_handle
 * Close a file or directory handle
 * Also frees handle resource and unlinks it from the SFTP structure
 */
LIBSSH2_API int
libssh2_sftp_close_handle(LIBSSH2_SFTP_HANDLE * handle)
{
    LIBSSH2_SFTP *sftp = handle->sftp;
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, retcode;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + handle_len(4) */
    ssize_t packet_len = handle->handle_len + 13;
    unsigned char *s, *data;
    int rc;

    if (handle->close_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Closing handle");
        s = handle->close_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!handle->close_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_CLOSE packet", 0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = SSH_FXP_CLOSE;
        handle->close_request_id = sftp->request_id++;
        libssh2_htonu32(s, handle->close_request_id);
        s += 4;
        libssh2_htonu32(s, handle->handle_len);
        s += 4;
        memcpy(s, handle->handle, handle->handle_len);
        s += handle->handle_len;

        handle->close_state = libssh2_NB_state_created;
    }

    if (handle->close_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0,
                                      (char *) handle->close_packet,
                                      packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_CLOSE command", 0);
            LIBSSH2_FREE(session, handle->close_packet);
            handle->close_packet = NULL;
            handle->close_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, handle->close_packet);
        handle->close_packet = NULL;

        handle->close_state = libssh2_NB_state_sent;
    }

    if (handle->close_state == libssh2_NB_state_sent) {
        rc = sftp_packet_require(sftp, SSH_FXP_STATUS,
                                 handle->close_request_id, &data,
                                 &data_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                          "Timeout waiting for status message", 0);
            handle->close_state = libssh2_NB_state_idle;
            return -1;
        }

        handle->close_state = libssh2_NB_state_sent1;
    }

    retcode = libssh2_ntohu32(data + 5);
    LIBSSH2_FREE(session, data);

    if (retcode != LIBSSH2_FX_OK) {
        sftp->last_errno = retcode;
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "SFTP Protocol Error", 0);
        handle->close_state = libssh2_NB_state_idle;
        return -1;
    }

    if (handle == sftp->handles) {
        sftp->handles = handle->next;
    }
    if (handle->next) {
        handle->next->prev = NULL;
    }

    if ((handle->handle_type == LIBSSH2_SFTP_HANDLE_DIR)
        && handle->u.dir.names_left) {
        LIBSSH2_FREE(session, handle->u.dir.names_packet);
    }

    handle->close_state = libssh2_NB_state_idle;

    LIBSSH2_FREE(session, handle);

    return 0;
}

/* }}} */

/* **********************
   * SFTP Miscellaneous *
   ********************** */

/* {{{ libssh2_sftp_unlink_ex
 * Delete a file from the remote server
 */
/* libssh2_sftp_unlink_ex - NB-UNSAFE?? */
LIBSSH2_API int
libssh2_sftp_unlink_ex(LIBSSH2_SFTP * sftp, const char *filename,
                       unsigned int filename_len)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, retcode;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + filename_len(4) */
    ssize_t packet_len = filename_len + 13;
    unsigned char *s, *data;
    int rc;

    if (sftp->unlink_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Unlinking %s", filename);
        s = sftp->unlink_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->unlink_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_REMOVE packet",
                          0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = SSH_FXP_REMOVE;
        sftp->unlink_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->unlink_request_id);
        s += 4;
        libssh2_htonu32(s, filename_len);
        s += 4;
        memcpy(s, filename, filename_len);
        s += filename_len;

        sftp->unlink_state = libssh2_NB_state_created;
    }

    if (sftp->unlink_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) sftp->unlink_packet,
                                      packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_REMOVE command", 0);
            LIBSSH2_FREE(session, sftp->unlink_packet);
            sftp->unlink_packet = NULL;
            sftp->unlink_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->unlink_packet);
        sftp->unlink_packet = NULL;

        sftp->unlink_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_require(sftp, SSH_FXP_STATUS,
                             sftp->unlink_request_id, &data,
                             &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    }
    else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->unlink_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->unlink_state = libssh2_NB_state_idle;

    retcode = libssh2_ntohu32(data + 5);
    LIBSSH2_FREE(session, data);

    if (retcode == LIBSSH2_FX_OK) {
        return 0;
    } else {
        sftp->last_errno = retcode;
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "SFTP Protocol Error", 0);
        return -1;
    }
}

/* }}} */

/* {{{ libssh2_sftp_rename_ex
 * Rename a file on the remote server
 */
LIBSSH2_API int
libssh2_sftp_rename_ex(LIBSSH2_SFTP * sftp, const char *source_filename,
                       unsigned int source_filename_len,
                       const char *dest_filename,
                       unsigned int dest_filename_len, long flags)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, retcode;
    ssize_t packet_len =
        source_filename_len + dest_filename_len + 17 + (sftp->version >=
                                                        5 ? 4 : 0);
    /* packet_len(4) + packet_type(1) + request_id(4) +
       source_filename_len(4) + dest_filename_len(4) + flags(4){SFTP5+) */
    unsigned char *data;
    int rc;

    if (sftp->version < 2) {
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "Server does not support RENAME", 0);
        return -1;
    }

    if (sftp->rename_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Renaming %s to %s",
                       source_filename, dest_filename);
        sftp->rename_s = sftp->rename_packet =
            LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->rename_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_RENAME packet",
                          0);
            return -1;
        }

        libssh2_htonu32(sftp->rename_s, packet_len - 4);
        sftp->rename_s += 4;
        *(sftp->rename_s++) = SSH_FXP_RENAME;
        sftp->rename_request_id = sftp->request_id++;
        libssh2_htonu32(sftp->rename_s, sftp->rename_request_id);
        sftp->rename_s += 4;
        libssh2_htonu32(sftp->rename_s, source_filename_len);
        sftp->rename_s += 4;
        memcpy(sftp->rename_s, source_filename, source_filename_len);
        sftp->rename_s += source_filename_len;
        libssh2_htonu32(sftp->rename_s, dest_filename_len);
        sftp->rename_s += 4;
        memcpy(sftp->rename_s, dest_filename, dest_filename_len);
        sftp->rename_s += dest_filename_len;

        if (sftp->version >= 5) {
            libssh2_htonu32(sftp->rename_s, flags);
            sftp->rename_s += 4;
        }

        sftp->rename_state = libssh2_NB_state_created;
    }

    if (sftp->rename_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) sftp->rename_packet,
                                      sftp->rename_s - sftp->rename_packet);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_RENAME command", 0);
            LIBSSH2_FREE(session, sftp->rename_packet);
            sftp->rename_packet = NULL;
            sftp->rename_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->rename_packet);
        sftp->rename_packet = NULL;

        sftp->rename_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_require(sftp, SSH_FXP_STATUS,
                             sftp->rename_request_id, &data,
                             &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->rename_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->rename_state = libssh2_NB_state_idle;

    retcode = libssh2_ntohu32(data + 5);
    LIBSSH2_FREE(session, data);

    switch (retcode) {
    case LIBSSH2_FX_OK:
        retcode = 0;
        break;

    case LIBSSH2_FX_FILE_ALREADY_EXISTS:
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "File already exists and SSH_FXP_RENAME_OVERWRITE not specified",
                      0);
        sftp->last_errno = retcode;
        retcode = -1;
        break;

    case LIBSSH2_FX_OP_UNSUPPORTED:
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "Operation Not Supported", 0);
        sftp->last_errno = retcode;
        retcode = -1;
        break;

    default:
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "SFTP Protocol Error", 0);
        sftp->last_errno = retcode;
        retcode = -1;
    }

    return retcode;
}

/* }}} */

/* {{{ libssh2_sftp_mkdir_ex
 * Create an SFTP directory
 */
LIBSSH2_API int
libssh2_sftp_mkdir_ex(LIBSSH2_SFTP * sftp, const char *path,
                      unsigned int path_len, long mode)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    LIBSSH2_SFTP_ATTRIBUTES attrs = {
        LIBSSH2_SFTP_ATTR_PERMISSIONS, 0, 0, 0, 0, 0, 0
    };
    unsigned long data_len, retcode, request_id;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + path_len(4) */
    ssize_t packet_len = path_len + 13 + libssh2_sftp_attrsize(&attrs);
    unsigned char *packet, *s, *data;
    int rc;

    if (sftp->mkdir_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP,
                       "Creating directory %s with mode 0%lo", path, mode);
        s = packet = LIBSSH2_ALLOC(session, packet_len);
        if (!packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_MKDIR packet", 0);
            return -1;
        }
        /* Filetype in SFTP 3 and earlier */
        attrs.permissions = mode | LIBSSH2_SFTP_ATTR_PFILETYPE_DIR;

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = SSH_FXP_MKDIR;
        request_id = sftp->request_id++;
        libssh2_htonu32(s, request_id);
        s += 4;
        libssh2_htonu32(s, path_len);
        s += 4;
        memcpy(s, path, path_len);
        s += path_len;
        s += libssh2_sftp_attr2bin(s, &attrs);

        sftp->mkdir_state = libssh2_NB_state_created;
    } else {
        packet = sftp->mkdir_packet;
        request_id = sftp->mkdir_request_id;
    }

    if (sftp->mkdir_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) packet, packet_len);
        if (rc == PACKET_EAGAIN) {
            sftp->mkdir_packet = packet;
            sftp->mkdir_request_id = request_id;
            return PACKET_EAGAIN;
        }
        if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_READ command", 0);
            LIBSSH2_FREE(session, packet);
            sftp->mkdir_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, packet);
        sftp->mkdir_state = libssh2_NB_state_sent;
        sftp->mkdir_packet = NULL;
    }

    rc = sftp_packet_require(sftp, SSH_FXP_STATUS, request_id, &data,
                             &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->mkdir_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->mkdir_state = libssh2_NB_state_idle;

    retcode = libssh2_ntohu32(data + 5);
    LIBSSH2_FREE(session, data);

    if (retcode == LIBSSH2_FX_OK) {
        return 0;
    } else {
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "SFTP Protocol Error", 0);
        sftp->last_errno = retcode;
        return -1;
    }
}

/* }}} */

/* {{{ libssh2_sftp_rmdir_ex
 * Remove a directory
 */
/* libssh2_sftp_rmdir_ex - NB-UNSAFE?? */
LIBSSH2_API int
libssh2_sftp_rmdir_ex(LIBSSH2_SFTP * sftp, const char *path,
                      unsigned int path_len)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, retcode;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + path_len(4) */
    ssize_t packet_len = path_len + 13;
    unsigned char *s, *data;
    int rc;

    if (sftp->rmdir_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "Removing directory: %s",
                       path);
        s = sftp->rmdir_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->rmdir_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_MKDIR packet", 0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        *(s++) = SSH_FXP_RMDIR;
        sftp->rmdir_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->rmdir_request_id);
        s += 4;
        libssh2_htonu32(s, path_len);
        s += 4;
        memcpy(s, path, path_len);
        s += path_len;

        sftp->rmdir_state = libssh2_NB_state_created;
    }

    if (sftp->rmdir_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) sftp->rmdir_packet,
                                      packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send FXP_MKDIR command", 0);
            LIBSSH2_FREE(session, sftp->rmdir_packet);
            sftp->rmdir_packet = NULL;
            sftp->rmdir_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->rmdir_packet);
        sftp->rmdir_packet = NULL;

        sftp->rmdir_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_require(sftp, SSH_FXP_STATUS,
                             sftp->rmdir_request_id, &data, &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->rmdir_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->rmdir_state = libssh2_NB_state_idle;

    retcode = libssh2_ntohu32(data + 5);
    LIBSSH2_FREE(session, data);

    if (retcode == LIBSSH2_FX_OK) {
        return 0;
    } else {
        sftp->last_errno = retcode;
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "SFTP Protocol Error", 0);
        return -1;
    }
}

/* }}} */

/* {{{ libssh2_sftp_stat_ex
 * Stat a file or symbolic link
 */
/* libssh2_sftp_stat_ex - NB-UNSAFE?? */
LIBSSH2_API int
libssh2_sftp_stat_ex(LIBSSH2_SFTP * sftp, const char *path,
                     unsigned int path_len, int stat_type,
                     LIBSSH2_SFTP_ATTRIBUTES * attrs)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + path_len(4) */
    ssize_t packet_len =
        path_len + 13 +
        ((stat_type ==
          LIBSSH2_SFTP_SETSTAT) ? libssh2_sftp_attrsize(attrs) : 0);
    unsigned char *s, *data;
    static const unsigned char stat_responses[2] =
        { SSH_FXP_ATTRS, SSH_FXP_STATUS };
    int rc;

    if (sftp->stat_state == libssh2_NB_state_idle) {
        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "%s %s",
                       (stat_type == LIBSSH2_SFTP_SETSTAT) ? "Set-statting" :
                       (stat_type ==
                        LIBSSH2_SFTP_LSTAT ? "LStatting" : "Statting"), path);
        s = sftp->stat_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->stat_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for FXP_MKDIR packet", 0);
            return -1;
        }

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        switch (stat_type) {
        case LIBSSH2_SFTP_SETSTAT:
            *(s++) = SSH_FXP_SETSTAT;
            break;

        case LIBSSH2_SFTP_LSTAT:
            *(s++) = SSH_FXP_LSTAT;
            break;

        case LIBSSH2_SFTP_STAT:
        default:
            *(s++) = SSH_FXP_STAT;
        }
        sftp->stat_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->stat_request_id);
        s += 4;
        libssh2_htonu32(s, path_len);
        s += 4;
        memcpy(s, path, path_len);
        s += path_len;
        if (stat_type == LIBSSH2_SFTP_SETSTAT) {
            s += libssh2_sftp_attr2bin(s, attrs);
        }

        sftp->stat_state = libssh2_NB_state_created;
    }

    if (sftp->stat_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0, (char *) sftp->stat_packet,
                                      packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send STAT/LSTAT/SETSTAT command", 0);
            LIBSSH2_FREE(session, sftp->stat_packet);
            sftp->stat_packet = NULL;
            sftp->stat_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->stat_packet);
        sftp->stat_packet = NULL;

        sftp->stat_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_requirev(sftp, 2, stat_responses,
                              sftp->stat_request_id, &data, &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->stat_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->stat_state = libssh2_NB_state_idle;

    if (data[0] == SSH_FXP_STATUS) {
        int retcode;

        retcode = libssh2_ntohu32(data + 5);
        LIBSSH2_FREE(session, data);
        if (retcode == LIBSSH2_FX_OK) {
            return 0;
        } else {
            sftp->last_errno = retcode;
            libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                          "SFTP Protocol Error", 0);
            return -1;
        }
    }

    memset(attrs, 0, sizeof(LIBSSH2_SFTP_ATTRIBUTES));
    libssh2_sftp_bin2attr(attrs, data + 5);
    LIBSSH2_FREE(session, data);

    return 0;
}

/* }}} */

/* {{{ libssh2_sftp_symlink_ex
 * Read or set a symlink
 */
LIBSSH2_API int
libssh2_sftp_symlink_ex(LIBSSH2_SFTP * sftp, const char *path,
                        unsigned int path_len, char *target,
                        unsigned int target_len, int link_type)
{
    LIBSSH2_CHANNEL *channel = sftp->channel;
    LIBSSH2_SESSION *session = channel->session;
    unsigned long data_len, link_len;
    /* 13 = packet_len(4) + packet_type(1) + request_id(4) + path_len(4) */
    ssize_t packet_len =
        path_len + 13 +
        ((link_type == LIBSSH2_SFTP_SYMLINK) ? (4 + target_len) : 0);
    unsigned char *s, *data;
    static const unsigned char link_responses[2] =
        { SSH_FXP_NAME, SSH_FXP_STATUS };
    int rc;

    if ((sftp->version < 3) && (link_type != LIBSSH2_SFTP_REALPATH)) {
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "Server does not support SYMLINK or READLINK", 0);
        return -1;
    }

    if (sftp->symlink_state == libssh2_NB_state_idle) {
        s = sftp->symlink_packet = LIBSSH2_ALLOC(session, packet_len);
        if (!sftp->symlink_packet) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for SYMLINK/READLINK"
                          "/REALPATH packet", 0);
            return -1;
        }

        _libssh2_debug(session, LIBSSH2_DBG_SFTP, "%s %s on %s",
                       (link_type ==
                        LIBSSH2_SFTP_SYMLINK) ? "Creating" : "Reading",
                       (link_type ==
                        LIBSSH2_SFTP_REALPATH) ? "realpath" : "symlink", path);

        libssh2_htonu32(s, packet_len - 4);
        s += 4;
        switch (link_type) {
        case LIBSSH2_SFTP_REALPATH:
            *(s++) = SSH_FXP_REALPATH;
            break;

        case LIBSSH2_SFTP_SYMLINK:
            *(s++) = SSH_FXP_SYMLINK;
            break;

        case LIBSSH2_SFTP_READLINK:
        default:
            *(s++) = SSH_FXP_READLINK;
        }
        sftp->symlink_request_id = sftp->request_id++;
        libssh2_htonu32(s, sftp->symlink_request_id);
        s += 4;
        libssh2_htonu32(s, path_len);
        s += 4;
        memcpy(s, path, path_len);
        s += path_len;
        if (link_type == LIBSSH2_SFTP_SYMLINK) {
            libssh2_htonu32(s, target_len);
            s += 4;
            memcpy(s, target, target_len);
            s += target_len;
        }

        sftp->symlink_state = libssh2_NB_state_created;
    }

    if (sftp->symlink_state == libssh2_NB_state_created) {
        rc = libssh2_channel_write_ex(channel, 0,
                                      (char *) sftp->symlink_packet,
                                      packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (packet_len != rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send SYMLINK/READLINK command", 0);
            LIBSSH2_FREE(session, sftp->symlink_packet);
            sftp->symlink_packet = NULL;
            sftp->symlink_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, sftp->symlink_packet);
        sftp->symlink_packet = NULL;

        sftp->symlink_state = libssh2_NB_state_sent;
    }

    rc = sftp_packet_requirev(sftp, 2, link_responses,
                              sftp->symlink_request_id, &data,
                              &data_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    }
    else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT,
                      "Timeout waiting for status message", 0);
        sftp->symlink_state = libssh2_NB_state_idle;
        return -1;
    }

    sftp->symlink_state = libssh2_NB_state_idle;

    if (data[0] == SSH_FXP_STATUS) {
        int retcode;

        retcode = libssh2_ntohu32(data + 5);
        LIBSSH2_FREE(session, data);
        if (retcode == LIBSSH2_FX_OK) {
            return 0;
        } else {
            sftp->last_errno = retcode;
            libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                          "SFTP Protocol Error", 0);
            return -1;
        }
    }

    if (libssh2_ntohu32(data + 5) < 1) {
        libssh2_error(session, LIBSSH2_ERROR_SFTP_PROTOCOL,
                      "Invalid READLINK/REALPATH response, no name entries",
                      0);
        LIBSSH2_FREE(session, data);
        return -1;
    }

    link_len = libssh2_ntohu32(data + 9);
    if (link_len >= target_len) {
        link_len = target_len - 1;
    }
    memcpy(target, data + 13, link_len);
    target[link_len] = 0;
    LIBSSH2_FREE(session, data);

    return link_len;
}

/* }}} */

/* {{{ libssh2_sftp_last_error
 * Returns the last error code reported by SFTP
 */
LIBSSH2_API unsigned long
libssh2_sftp_last_error(LIBSSH2_SFTP * sftp)
{
    return sftp->last_errno;
}

/* }}} */
