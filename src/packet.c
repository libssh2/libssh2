/* Copyright (c) 2004-2007, Sara Golemon <sarag@libssh2.org>
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
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include <sys/types.h>

/* {{{ libssh2_packet_queue_listener
 * Queue a connection request for a listener
 */
static inline int 
libssh2_packet_queue_listener(LIBSSH2_SESSION *session, unsigned char *data,
                              unsigned long datalen,
                              packet_queue_listener_state_t *listen_state)
{
    /*
     * Look for a matching listener
     */
    unsigned char *s = data + (sizeof("forwarded-tcpip") - 1) + 5;
    /* 17 = packet_type(1) + channel(4) + reason(4) + descr(4) + lang(4) */
    unsigned long packet_len = 17 + (sizeof(FwdNotReq) - 1);
    unsigned char *p;
    LIBSSH2_LISTENER *listen = session->listeners;
    char failure_code = 1; /* SSH_OPEN_ADMINISTRATIVELY_PROHIBITED */
    int rc;
    
    (void)datalen;
    
    if (listen_state->state == libssh2_NB_state_idle) {
        listen_state->sender_channel = libssh2_ntohu32(s);        s += 4;
        
        listen_state->initial_window_size = libssh2_ntohu32(s);   s += 4;
        listen_state->packet_size = libssh2_ntohu32(s);           s += 4;
        
        listen_state->host_len = libssh2_ntohu32(s);              s += 4;
        listen_state->host = s;                   s += listen_state->host_len;
        listen_state->port = libssh2_ntohu32(s);                  s += 4;
        
        listen_state->shost_len = libssh2_ntohu32(s);             s += 4;
        listen_state->shost = s;                  s += listen_state->shost_len;
        listen_state->sport = libssh2_ntohu32(s);                 s += 4;
        
        _libssh2_debug(session, LIBSSH2_DBG_CONN,
                       "Remote received connection from %s:%ld to %s:%ld",
                       listen_state->shost, listen_state->sport,
                       listen_state->host, listen_state->port);
        
        listen_state->state = libssh2_NB_state_allocated;
    }
    
    if (listen_state->state != libssh2_NB_state_sent) {
        while (listen) {
            if ((listen->port == (int)listen_state->port) &&
                (strlen(listen->host) == listen_state->host_len) &&
                (memcmp(listen->host, listen_state->host, listen_state->host_len) == 0)) {
                /* This is our listener */
                LIBSSH2_CHANNEL *channel, *last_queued = listen->queue;
                
                last_queued = listen->queue;
                if (listen_state->state == libssh2_NB_state_allocated) {
                    if (listen->queue_maxsize &&
                        (listen->queue_maxsize <= listen->queue_size)) {
                        /* Queue is full */
                        failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
                        _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                       "Listener queue full, ignoring");
                        listen_state->state = libssh2_NB_state_sent;
                        break;
                    }
                    
                    channel = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_CHANNEL));
                    if (!channel) {
                        libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                      "Unable to allocate a channel for new connection",
                                      0);
                        failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
                        listen_state->state = libssh2_NB_state_sent;
                        break;
                    }
                    memset(channel, 0, sizeof(LIBSSH2_CHANNEL));
                    
                    channel->session = session;
                    channel->channel_type_len = sizeof("forwarded-tcpip") - 1;
                    channel->channel_type = LIBSSH2_ALLOC(session,
                                                          channel->channel_type_len + 1);
                    if (!channel->channel_type) {
                        libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                      "Unable to allocate a channel for new connection",
                                      0);
                        LIBSSH2_FREE(session, channel);
                        failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
                        listen_state->state = libssh2_NB_state_sent;
                        break;
                    }
                    memcpy(channel->channel_type, "forwarded-tcpip",
                           channel->channel_type_len + 1);
                    
                    channel->remote.id = listen_state->sender_channel;
                    channel->remote.window_size_initial = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
                    channel->remote.window_size = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
                    channel->remote.packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT;
                    
                    channel->local.id = libssh2_channel_nextid(session);
                    channel->local.window_size_initial = listen_state->initial_window_size;
                    channel->local.window_size = listen_state->initial_window_size;
                    channel->local.packet_size = listen_state->packet_size;
                    
                    _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                   "Connection queued: channel %lu/%lu win %lu/%lu packet %lu/%lu",
                                   channel->local.id, channel->remote.id,
                                   channel->local.window_size,
                                   channel->remote.window_size,
                                   channel->local.packet_size,
                                   channel->remote.packet_size);
                    
                    p = listen_state->packet;
                    *(p++) = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
                    libssh2_htonu32(p, channel->remote.id);
                    p += 4;
                    libssh2_htonu32(p, channel->local.id);
                    p += 4;
                    libssh2_htonu32(p, channel->remote.window_size_initial);
                    p += 4;
                    libssh2_htonu32(p, channel->remote.packet_size);
                    p += 4;
                    
                    listen_state->state = libssh2_NB_state_created;
                }
                
                if (listen_state->state == libssh2_NB_state_created) {
                    rc = libssh2_packet_write(session, listen_state->packet,
                                              17);
                    if (rc == PACKET_EAGAIN) {
                        return PACKET_EAGAIN;
                    }
                    else if (rc) {
                        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                                      "Unable to send channel open confirmation",
                                      0);
                        listen_state->state = libssh2_NB_state_idle;
                        return -1;
                    }
                    
                    /* Link the channel into the end of the queue list */
                    
                    if (!last_queued) {
                        listen->queue = channel;
                        listen_state->state = libssh2_NB_state_idle;
                        return 0;
                    }
                    
                    while (last_queued->next) {
                        last_queued = last_queued->next;
                    }
                    
                    last_queued->next = channel;
                    channel->prev = last_queued;
                    
                    listen->queue_size++;
                    
                    listen_state->state = libssh2_NB_state_idle;
                    return 0;
                }
            }
            
            listen = listen->next;
        }
        
        listen_state->state = libssh2_NB_state_sent;
    }
    
    /* We're not listening to you */
    {
        p = listen_state->packet;
        *(p++) = SSH_MSG_CHANNEL_OPEN_FAILURE;
        libssh2_htonu32(p, listen_state->sender_channel);
        p += 4;
        libssh2_htonu32(p, failure_code);
        p += 4;
        libssh2_htonu32(p, sizeof(FwdNotReq) - 1);
        p += 4;
        memcpy(s, FwdNotReq, sizeof(FwdNotReq) - 1);
        p += sizeof(FwdNotReq) - 1;
        libssh2_htonu32(p, 0);
        
        rc = libssh2_packet_write(session, listen_state->packet, packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
        else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send open failure", 0);
            listen_state->state = libssh2_NB_state_idle;
            return -1;
        }
        listen_state->state = libssh2_NB_state_idle;
        return 0;
    }
}
/* }}} */

/* {{{ libssh2_packet_x11_open
 * Accept a forwarded X11 connection
 */
static inline int 
libssh2_packet_x11_open(LIBSSH2_SESSION *session,  unsigned char *data,
                        unsigned long datalen,
                        packet_x11_open_state_t *x11open_state)
{
    int failure_code = 2; /* SSH_OPEN_CONNECT_FAILED */
    unsigned char *s = data + (sizeof("x11") - 1) + 5;
    /* 17 = packet_type(1) + channel(4) + reason(4) + descr(4) + lang(4) */
    unsigned long packet_len = 17 + (sizeof(X11FwdUnAvil) - 1);
    unsigned char *p;
    LIBSSH2_CHANNEL *channel;
    int rc;
    
    (void)datalen;
    
    if (x11open_state->state == libssh2_NB_state_idle) {
        x11open_state->sender_channel = libssh2_ntohu32(s);         s += 4;
        x11open_state->initial_window_size = libssh2_ntohu32(s);    s += 4;
        x11open_state->packet_size = libssh2_ntohu32(s);            s += 4;
        x11open_state->shost_len = libssh2_ntohu32(s);              s += 4;
        x11open_state->shost = s;               s += x11open_state->shost_len;
        x11open_state->sport = libssh2_ntohu32(s);                  s += 4;
        
        _libssh2_debug(session, LIBSSH2_DBG_CONN,
                       "X11 Connection Received from %s:%ld on channel %lu",
                       x11open_state->shost, x11open_state->sport,
                       x11open_state->sender_channel);
        
        x11open_state->state = libssh2_NB_state_allocated;
    }
    
    if (session->x11) {
        if (x11open_state->state == libssh2_NB_state_allocated) {
            channel = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_CHANNEL));
            if (!channel) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate a channel for new connection",
                              0);
                failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
                goto x11_exit;
            }
            memset(channel, 0, sizeof(LIBSSH2_CHANNEL));
            
            channel->session = session;
            channel->channel_type_len = sizeof("x11") - 1;
            channel->channel_type = LIBSSH2_ALLOC(session,
                                                  channel->channel_type_len + 1);
            if (!channel->channel_type) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate a channel for new connection",
                              0);
                LIBSSH2_FREE(session, channel);
                failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
                goto x11_exit;
            }
            memcpy(channel->channel_type, "x11", channel->channel_type_len + 1);
            
            channel->remote.id = x11open_state->sender_channel;
            channel->remote.window_size_initial = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
            channel->remote.window_size = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
            channel->remote.packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT;
            
            channel->local.id = libssh2_channel_nextid(session);
            channel->local.window_size_initial = x11open_state->initial_window_size;
            channel->local.window_size = x11open_state->initial_window_size;
            channel->local.packet_size = x11open_state->packet_size;
            
            _libssh2_debug(session, LIBSSH2_DBG_CONN,
                           "X11 Connection established: channel %lu/%lu win %lu/%lu packet %lu/%lu",
                           channel->local.id, channel->remote.id,
                           channel->local.window_size,
                           channel->remote.window_size,
                           channel->local.packet_size,
                           channel->remote.packet_size);
            p = x11open_state->packet;
            *(p++) = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
            libssh2_htonu32(p, channel->remote.id);                     p += 4;
            libssh2_htonu32(p, channel->local.id);                      p += 4;
            libssh2_htonu32(p, channel->remote.window_size_initial);    p += 4;
            libssh2_htonu32(p, channel->remote.packet_size);            p += 4;
            
            x11open_state->state = libssh2_NB_state_created;
        }
        
        if (x11open_state->state == libssh2_NB_state_created) {
            rc = libssh2_packet_write(session, x11open_state->packet, 17);
            if (rc == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            }
            else if (rc) {
                libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                              "Unable to send channel open confirmation", 0);
                x11open_state->state = libssh2_NB_state_idle;
                return -1;
            }
            
            /* Link the channel into the session */
            if (session->channels.tail) {
                session->channels.tail->next = channel;
                channel->prev = session->channels.tail;
            } else {
                session->channels.head = channel;
                channel->prev = NULL;
            }
            channel->next = NULL;
            session->channels.tail = channel;
            
            /*
             * Pass control to the callback, they may turn right around and
             * free the channel, or actually use it
             */
            LIBSSH2_X11_OPEN(channel, (char *)x11open_state->shost, x11open_state->sport);
            
            x11open_state->state = libssh2_NB_state_idle;
            return 0;
        }
    } else {
        failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
    }
    
x11_exit:
    p = x11open_state->packet;
    *(p++) = SSH_MSG_CHANNEL_OPEN_FAILURE;
    libssh2_htonu32(p, x11open_state->sender_channel);      p += 4;
    libssh2_htonu32(p, failure_code);                       p += 4;
    libssh2_htonu32(p, sizeof(X11FwdUnAvil) - 1);           p += 4;
    memcpy(s, X11FwdUnAvil, sizeof(X11FwdUnAvil) - 1);
                                                p += sizeof(X11FwdUnAvil) - 1;
    libssh2_htonu32(p, 0);
    
    rc = libssh2_packet_write(session, x11open_state->packet, packet_len);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    }
    else if (rc) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                      "Unable to send open failure", 0);
        x11open_state->state = libssh2_NB_state_idle;
        return -1;
    }
    x11open_state->state = libssh2_NB_state_idle;
    return 0;
}
/* }}} */

/* {{{ libssh2_packet_new
 * Create a new packet and attach it to the brigade
 */
int libssh2_packet_add(LIBSSH2_SESSION *session, unsigned char *data,
                       size_t datalen, int macstate)
{
    int rc;
    
    if (session->packAdd_state == libssh2_NB_state_idle) {
        session->packAdd_data_head = 0;
    
        /* Zero the whole thing out */
        memset(&session->packAdd_key_state, 0,
               sizeof(session->packAdd_key_state));
        
        /* Zero the whole thing out */
        memset(&session->packAdd_Qlstn_state, 0,
               sizeof(session->packAdd_Qlstn_state));
        
        /* Zero the whole thing out */
        memset(&session->packAdd_x11open_state, 0,
               sizeof(session->packAdd_x11open_state));
        
        _libssh2_debug(session, LIBSSH2_DBG_TRANS,
                       "Packet type %d received, length=%d",
                       (int)data[0], (int)datalen);
        if (macstate == LIBSSH2_MAC_INVALID) {
            if (session->macerror) {
                if (LIBSSH2_MACERROR(session, (char *)data, datalen) == 0) {
                    /* Calling app has given the OK, Process it anyway */
                    macstate = LIBSSH2_MAC_CONFIRMED;
                } else {
                    libssh2_error(session, LIBSSH2_ERROR_INVALID_MAC,
                                  "Invalid Message Authentication Code received",
                                  0);
                    if (session->ssh_msg_disconnect) {
                        LIBSSH2_DISCONNECT(session, SSH_DISCONNECT_MAC_ERROR,
                                           "Invalid MAC received",
                                           sizeof("Invalid MAC received") - 1,
                                           "", 0);
                    }
                    LIBSSH2_FREE(session, data);
                    return -1;
                }
            } else {
                libssh2_error(session, LIBSSH2_ERROR_INVALID_MAC,
                              "Invalid Message Authentication Code received",
                              0);
                if (session->ssh_msg_disconnect) {
                    LIBSSH2_DISCONNECT(session, SSH_DISCONNECT_MAC_ERROR,
                                       "Invalid MAC received",
                                       sizeof("Invalid MAC received") - 1,
                                       "", 0);
                }
                LIBSSH2_FREE(session, data);
                return -1;
            }
        }
        
        session->packAdd_state = libssh2_NB_state_allocated;
    }

    /*
     * =============================== NOTE ===============================
     * I know this is very ugly and not a really good use of "goto", but
     * this case statement would be even uglier to do it any other way
     */
    if (session->packAdd_state == libssh2_NB_state_jump1) {
        goto libssh2_packet_add_jump_point1;
    }
    else if (session->packAdd_state == libssh2_NB_state_jump2) {
        goto libssh2_packet_add_jump_point2;
    }
    else if (session->packAdd_state == libssh2_NB_state_jump3) {
        goto libssh2_packet_add_jump_point3;
    }
    
    if (session->packAdd_state == libssh2_NB_state_allocated) {
        /* A couple exceptions to the packet adding rule: */
        switch (data[0]) {
            case SSH_MSG_DISCONNECT:
                {
                    char *message, *language;
                    int reason, message_len, language_len;
                    
                    reason = libssh2_ntohu32(data + 1);
                    message_len = libssh2_ntohu32(data + 5);
                    /* 9 = packet_type(1) + reason(4) + message_len(4) */
                    message = (char *)data + 9;
                    language_len = libssh2_ntohu32(data + 9 + message_len);
                    /*
                     * This is where we hack on the data a little,
                     * Use the MSB of language_len to to a terminating NULL
                     * (In all liklihood it is already)
                     * Shift the language tag back a byte (In all likelihood
                     * it's zero length anyway)
                     * Store a NULL in the last byte of the packet to terminate
                     * the language string
                     * With the lengths passed this isn't *REALLY* necessary,
                     * but it's "kind"
                     */
                    message[message_len] = '\0';
                    language = (char *)data + 9 + message_len + 3;
                    if (language_len) {
                        memcpy(language, language + 1, language_len);
                    }
                    language[language_len] = '\0';
                    
                    if (session->ssh_msg_disconnect) {
                        LIBSSH2_DISCONNECT(session, reason, message,
                                           message_len, language, language_len);
                    }
                    _libssh2_debug(session, LIBSSH2_DBG_TRANS,
                                   "Disconnect(%d): %s(%s)", reason,
                                   message, language);
                    LIBSSH2_FREE(session, data);
                    session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
                    session->packAdd_state = libssh2_NB_state_idle;
                    return -1;
                }
                break;
                
            case SSH_MSG_IGNORE:
                /* As with disconnect, back it up one and add a trailing NULL */
                memcpy(data + 4, data + 5, datalen - 5);
                data[datalen] = '\0';
                if (session->ssh_msg_ignore) {
                    LIBSSH2_IGNORE(session, (char *)data + 4, datalen - 5);
                }
                LIBSSH2_FREE(session, data);
                session->packAdd_state = libssh2_NB_state_idle;
                return 0;
                break;
                
            case SSH_MSG_DEBUG:
                {
                    int always_display = data[0];
                    char *message, *language;
                    int message_len, language_len;
                    
                    message_len = libssh2_ntohu32(data + 2);
                    /* 6 = packet_type(1) + display(1) + message_len(4) */
                    message = (char *)data + 6;
                    language_len = libssh2_ntohu32(data + 6 + message_len);
                    /*
                     * This is where we hack on the data a little,
                     * Use the MSB of language_len to to a terminating NULL
                     * (In all liklihood it is already)
                     * Shift the language tag back a byte (In all likelihood
                     * it's zero length anyway)
                     * Store a NULL in the last byte of the packet to terminate
                     * the language string
                     * With the lengths passed this isn't *REALLY* necessary,
                     * but it's "kind"
                     */
                    message[message_len] = '\0';
                    language = (char *)data + 6 + message_len + 3;
                    if (language_len) {
                        memcpy(language, language + 1, language_len);
                    }
                    language[language_len] = '\0';
                    
                    if (session->ssh_msg_debug) {
                        LIBSSH2_DEBUG(session, always_display, message,
                                      message_len, language, language_len);
                    }
                    /*
                     * _libssh2_debug will actually truncate this for us so
                     * that it's not an inordinate about of data
                     */
                    _libssh2_debug(session, LIBSSH2_DBG_TRANS,
                                   "Debug Packet: %s", message);
                    LIBSSH2_FREE(session, data);
                    session->packAdd_state = libssh2_NB_state_idle;
                    return 0;
                }
                break;
                
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                /* streamid(4) */
                session->packAdd_data_head += 4;
            case SSH_MSG_CHANNEL_DATA:
                /* packet_type(1) + channelno(4) + datalen(4) */
                session->packAdd_data_head += 9;
                {
                    session->packAdd_channel = libssh2_channel_locate(session,
                                                                      libssh2_ntohu32(data + 1));
                    
                    if (!session->packAdd_channel) {
                        libssh2_error(session, LIBSSH2_ERROR_CHANNEL_UNKNOWN,
                                      "Packet received for unknown channel, ignoring",
                                      0);
                        LIBSSH2_FREE(session, data);
                        session->packAdd_state = libssh2_NB_state_idle;
                        return 0;
                    }
#ifdef LIBSSH2DEBUG
                    {
                        unsigned long stream_id = 0;
                        
                        if (data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA) {
                            stream_id = libssh2_ntohu32(data + 5);
                        }
                        
                        _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                       "%d bytes received for channel %lu/%lu stream #%lu",
                                       (int)(datalen - session->packAdd_data_head),
                                       session->packAdd_channel->local.id,
                                       session->packAdd_channel->remote.id,
                                       stream_id);
                    }
#endif
                    if ((session->packAdd_channel->remote.extended_data_ignore_mode == LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE) &&
                        (data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA)) {
                        /* Pretend we didn't receive this */
                        LIBSSH2_FREE(session, data);
                        
                        _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                       "Ignoring extended data and refunding %d bytes",
                                       (int)(datalen - 13));
                        /* Adjust the window based on the block we just freed */
libssh2_packet_add_jump_point1:
                        session->packAdd_state = libssh2_NB_state_jump1;
                        rc = libssh2_channel_receive_window_adjust(session->packAdd_channel,
                                                                   datalen - 13, 0);
                        if (rc == PACKET_EAGAIN) {
                            return PACKET_EAGAIN;
                        }
                        session->packAdd_state = libssh2_NB_state_idle;
                        return 0;
                    }
                    
                    /*
                     * REMEMBER! remote means remote as source of data,
                     * NOT remote window!
                     */
                    if (session->packAdd_channel->remote.packet_size < (datalen - session->packAdd_data_head)) {
                        /*
                         * Spec says we MAY ignore bytes sent beyond 
                         * packet_size
                         */
                        libssh2_error(session,
                                      LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED,
                                      "Packet contains more data than we offered to receive, truncating",
                                      0);
                        datalen = session->packAdd_channel->remote.packet_size + session->packAdd_data_head;
                    }
                    if (session->packAdd_channel->remote.window_size <= 0) {
                        /*
                         * Spec says we MAY ignore bytes sent beyond
                         * window_size
                         */
                        libssh2_error(session,
                                      LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED,
                                      "The current receive window is full, data ignored",
                                      0);
                        LIBSSH2_FREE(session, data);
                        session->packAdd_state = libssh2_NB_state_idle;
                        return 0;
                    }
                    /* Reset EOF status */
                    session->packAdd_channel->remote.eof = 0;
                    
                    if ((datalen - session->packAdd_data_head) > session->packAdd_channel->remote.window_size) {
                        libssh2_error(session,
                                      LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED,
                                      "Remote sent more data than current window allows, truncating",
                                      0);
                        datalen = session->packAdd_channel->remote.window_size + session->packAdd_data_head;
                    } else {
                        /* Now that we've received it, shrink our window */
                        session->packAdd_channel->remote.window_size -= datalen - session->packAdd_data_head;
                    }
                }
                break;
                
            case SSH_MSG_CHANNEL_EOF:
                {
                    session->packAdd_channel = libssh2_channel_locate(session,
                                                                      libssh2_ntohu32(data + 1));
                    
                    if (!session->packAdd_channel) {
                        /* We may have freed already, just quietly ignore this... */
                        LIBSSH2_FREE(session, data);
                        session->packAdd_state = libssh2_NB_state_idle;
                        return 0;
                    }
                    
                    _libssh2_debug(session,
                                   LIBSSH2_DBG_CONN,
                                   "EOF received for channel %lu/%lu",
                                   session->packAdd_channel->local.id,
                                   session->packAdd_channel->remote.id);
                    session->packAdd_channel->remote.eof = 1;
                    
                    LIBSSH2_FREE(session, data);
                    session->packAdd_state = libssh2_NB_state_idle;
                    return 0;
                }
                break;
                
            case SSH_MSG_CHANNEL_REQUEST:
                {
                    if (libssh2_ntohu32(data+5) == sizeof("exit-status") - 1
                        && !memcmp("exit-status", data + 9, sizeof("exit-status") - 1)) {
                        
                        /* we've got "exit-status" packet. Set the session value */
                        session->packAdd_channel = libssh2_channel_locate(session, libssh2_ntohu32(data+1));
                        
                        if (session->packAdd_channel) {
                            session->packAdd_channel->exit_status = libssh2_ntohu32(data + 9 + sizeof("exit-status"));
                            _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                           "Exit status %lu received for channel %lu/%lu",
                                           session->packAdd_channel->exit_status,
                                           session->packAdd_channel->local.id,
                                           session->packAdd_channel->remote.id);
                        }
                        
                        LIBSSH2_FREE(session, data);
                        session->packAdd_state = libssh2_NB_state_idle;
                        return 0;
                    }
                }
                break;
                
            case SSH_MSG_CHANNEL_CLOSE:
                {
                    session->packAdd_channel = libssh2_channel_locate(session,
                                                                      libssh2_ntohu32(data + 1));
                    
                    if (!session->packAdd_channel) {
                        /* We may have freed already, just quietly ignore this... */
                        LIBSSH2_FREE(session, data);
                        session->packAdd_state = libssh2_NB_state_idle;
                        return 0;
                    }
                    _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                   "Close received for channel %lu/%lu",
                                   session->packAdd_channel->local.id,
                                   session->packAdd_channel->remote.id);
                    
                    session->packAdd_channel->remote.close = 1;
                    session->packAdd_channel->remote.eof = 1;
                    /* TODO: Add a callback for this */
                    
                    LIBSSH2_FREE(session, data);
                    session->packAdd_state = libssh2_NB_state_idle;
                    return 0;
                }
                break;
                
            case SSH_MSG_CHANNEL_OPEN:
                if ((datalen >= (sizeof("forwarded-tcpip") + 4)) &&
                    ((sizeof("forwarded-tcpip")-1) == libssh2_ntohu32(data + 1)) &&
                    (memcmp(data + 5, "forwarded-tcpip", sizeof("forwarded-tcpip") - 1) == 0)) {
                    
libssh2_packet_add_jump_point2:
                    session->packAdd_state = libssh2_NB_state_jump2;
                    rc = libssh2_packet_queue_listener(session, data, datalen,
                                                       &session->packAdd_Qlstn_state);
                    if (rc == PACKET_EAGAIN) {
                        return PACKET_EAGAIN;
                    }
                    
                    LIBSSH2_FREE(session, data);
                    session->packAdd_state = libssh2_NB_state_idle;
                    return rc;
                }
                if ((datalen >= (sizeof("x11") + 4)) &&
                    ((sizeof("x11")-1) == libssh2_ntohu32(data + 1)) &&
                    (memcmp(data + 5, "x11", sizeof("x11") - 1) == 0)) {
                    
libssh2_packet_add_jump_point3:
                    session->packAdd_state = libssh2_NB_state_jump3;
                    rc = libssh2_packet_x11_open(session, data, datalen,
                                                 &session->packAdd_x11open_state);
                    if (rc == PACKET_EAGAIN) {
                        return PACKET_EAGAIN;
                    }
                    
                    LIBSSH2_FREE(session, data);
                    session->packAdd_state = libssh2_NB_state_idle;
                    return rc;
                }
                break;
                
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                {
                    unsigned long bytestoadd = libssh2_ntohu32(data + 5);
                    session->packAdd_channel = libssh2_channel_locate(session,
                                                                      libssh2_ntohu32(data + 1));
                    
                    if (session->packAdd_channel && bytestoadd) {
                        session->packAdd_channel->local.window_size += bytestoadd;
                    }
                    _libssh2_debug(session, LIBSSH2_DBG_CONN,
                                   "Window adjust received for channel %lu/%lu, adding %lu bytes, new window_size=%lu",
                                   session->packAdd_channel->local.id,
                                   session->packAdd_channel->remote.id,
                                   bytestoadd,
                                   session->packAdd_channel->local.window_size);
                    
                    LIBSSH2_FREE(session, data);
                    session->packAdd_state = libssh2_NB_state_idle;
                    return 0;
                }
                break;
        }
        
        session->packAdd_state = libssh2_NB_state_sent;
    }
    
    if (session->packAdd_state == libssh2_NB_state_sent) {
        session->packAdd_packet = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_PACKET));
        if (!session->packAdd_packet) {
            _libssh2_debug(session, LIBSSH2_ERROR_ALLOC,
                           "Unable to allocate memory for LIBSSH2_PACKET");
            LIBSSH2_FREE(session, data);
            session->packAdd_state = libssh2_NB_state_idle;
            return -1;
        }
        memset(session->packAdd_packet, 0, sizeof(LIBSSH2_PACKET));
        
        session->packAdd_packet->data = data;
        session->packAdd_packet->data_len = datalen;
        session->packAdd_packet->data_head = session->packAdd_data_head;
        session->packAdd_packet->mac = macstate;
        session->packAdd_packet->brigade = &session->packets;
        session->packAdd_packet->next = NULL;
        
        if (session->packets.tail) {
            session->packAdd_packet->prev = session->packets.tail;
            session->packAdd_packet->prev->next = session->packAdd_packet;
            session->packets.tail = session->packAdd_packet;
        } else {
            session->packets.head = session->packAdd_packet;
            session->packets.tail = session->packAdd_packet;
            session->packAdd_packet->prev = NULL;
        }
        
        session->packAdd_state = libssh2_NB_state_sent1;
    }
    
    if ((data[0] == SSH_MSG_KEXINIT &&
         !(session->state & LIBSSH2_STATE_EXCHANGING_KEYS)) ||
        (session->packAdd_state == libssh2_NB_state_sent2)) {
        if (session->packAdd_state == libssh2_NB_state_sent1) {
            /*
             * Remote wants new keys
             * Well, it's already in the brigade,
             * let's just call back into ourselves
             */
            _libssh2_debug(session, LIBSSH2_DBG_TRANS, "Renegotiating Keys");
            
            session->packAdd_state = libssh2_NB_state_sent2;
        }
        /*
         * If there was a key reexchange failure, let's just hope we didn't
         * send NEWKEYS yet, otherwise remote will drop us like a rock
         */
        rc = libssh2_kex_exchange(session, 1, &session->packAdd_key_state);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
    }
    
    session->packAdd_state = libssh2_NB_state_idle;
    return 0;
}
/* }}} */

/* {{{ libssh2_packet_ask
 * Scan the brigade for a matching packet type, optionally poll the socket for
 * a packet first
 */
int libssh2_packet_ask_ex(LIBSSH2_SESSION *session, unsigned char packet_type, unsigned char **data, unsigned long *data_len,
                          unsigned long match_ofs, const unsigned char *match_buf, unsigned long match_len, int poll_socket)
{
    LIBSSH2_PACKET *packet = session->packets.head;
    
    if (poll_socket) {
        /*
         * XXX CHECK ***
         * When "poll_socket" is "1" libhss2_packet_read() can return
         * PACKET_EAGAIN.  I am not sure what should happen, but internally
         * there is only one location that might do so, libssh2_packet_askv_ex()
         */
        libssh2pack_t rc = libssh2_packet_read(session);
        if ((rc < 0) && !packet) {
            return rc;
        }
    }
    _libssh2_debug(session, LIBSSH2_DBG_TRANS,
                   "Looking for packet of type: %d", (int)packet_type);
    
    while (packet) {
        if (packet->data[0] == packet_type && (packet->data_len >= (match_ofs + match_len)) &&
            (!match_buf || (memcmp(packet->data + match_ofs, match_buf, match_len) == 0))) {
            *data = packet->data;
            *data_len = packet->data_len;
            
            if (packet->prev) {
                packet->prev->next = packet->next;
            } else {
                session->packets.head = packet->next;
            }
            
            if (packet->next) {
                packet->next->prev = packet->prev;
            } else {
                session->packets.tail = packet->prev;
            }
            
            LIBSSH2_FREE(session, packet);
            
            return 0;
        }
        packet = packet->next;
    }
    return -1;
}
/* }}} */

/* {{{ libssh2_packet_askv
 * Scan for any of a list of packet types in the brigade, optionally poll the
 * socket for a packet first
 */
int libssh2_packet_askv_ex(LIBSSH2_SESSION *session,
                           const unsigned char *packet_types,
                           unsigned char **data, unsigned long *data_len,
                           unsigned long match_ofs,
                           const unsigned char *match_buf,
                           unsigned long match_len, int poll_socket)
{
    int i, packet_types_len = strlen((char *)packet_types);
    
    for(i = 0; i < packet_types_len; i++) {
        /*
         * XXX CHECK XXX
         * When "poll_socket" is "1" libssh2_packet_ask_ex() could
         * return PACKET_EAGAIN.  Not sure the correct action, I 
         * think it is right as is.
         */
        if (0 == libssh2_packet_ask_ex(session, packet_types[i], data, 
                                       data_len, match_ofs, match_buf, 
                                       match_len, i ? 0 : poll_socket)) {
            return 0;
        }
    }
    
    return -1;
}
/* }}} */

/* {{{ waitsocket
 * Returns
 * negative on error
 * >0 on incoming data
 * 0 on timeout
 *
 * FIXME: convert to use poll on systems that have it.
 */
int libssh2_waitsocket(LIBSSH2_SESSION *session, long seconds)
{
    struct timeval timeout;
    int rc;
    fd_set fd;

    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;

    FD_ZERO(&fd);

    FD_SET(session->socket_fd, &fd);

    rc = select(session->socket_fd+1, &fd, NULL, NULL, &timeout);

    return rc;
}

/* {{{ libssh2_packet_require
 * Loops libssh2_packet_read() until the packet requested is available
 * SSH_DISCONNECT or a SOCKET_DISCONNECTED will cause a bailout
 *
 * Returns negative on error
 * Returns 0 when it has taken care of the requested packet.
 */
int libssh2_packet_require_ex(LIBSSH2_SESSION *session, unsigned char packet_type, unsigned char **data,
                              unsigned long *data_len, unsigned long match_ofs, const unsigned char *match_buf,
                              unsigned long match_len, packet_require_state_t *state)
{
    if (state->start == 0) {
        if (libssh2_packet_ask_ex(session, packet_type, data, data_len, match_ofs, match_buf, match_len, 0) == 0) {
            /* A packet was available in the packet brigade */
            return 0;
        }
        
        state->start = time(NULL);
        
        _libssh2_debug(session, LIBSSH2_DBG_TRANS, "May block until packet of type %d becomes available", (int)packet_type);
    }
    
    while (session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
        libssh2pack_t ret = libssh2_packet_read(session);
        if (ret == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
        else if ((ret == 0) && (!session->socket_block)) {
            /* If we are in non-blocking and there is no data, return that */
            return PACKET_EAGAIN;
        }
        else if (ret < 0) {
            state->start = 0;
            /* an error which is not just because of blocking */
            return ret;
        }
        else if (ret == packet_type) {
            /* Be lazy, let packet_ask pull it out of the brigade */
            ret = libssh2_packet_ask_ex(session, packet_type, data, data_len, match_ofs, match_buf, match_len, 0);
            state->start = 0;
            return ret;
        }
        else if (ret == 0) {
            /* nothing available, wait until data arrives or we time out */
            long left = LIBSSH2_READ_TIMEOUT - (time(NULL) - state->start);
            
            if ((left <= 0) || (libssh2_waitsocket(session, left) <= 0)) {
                state->start = 0;
                return PACKET_TIMEOUT;
            }
        }
    }
    
    /* Only reached if the socket died */
    return -1;
}
/* }}} */

/* {{{ libssh2_packet_burn
 * Loops libssh2_packet_read() until any packet is available and promptly 
 * discards it
 * Used during KEX exchange to discard badly guessed KEX_INIT packets
 */
int libssh2_packet_burn(LIBSSH2_SESSION *session, libssh2_nonblocking_states *state)
{
    unsigned char *data;
    unsigned long data_len;
    unsigned char all_packets[255];
    int i;
    int ret;
    
    if (*state == libssh2_NB_state_idle) {
        for(i = 1; i < 256; i++) {
            all_packets[i - 1] = i;
        }
        
        if (libssh2_packet_askv_ex(session, all_packets, &data, &data_len, 0, NULL, 0, 0) == 0) {
            i = data[0];
            /* A packet was available in the packet brigade, burn it */
            LIBSSH2_FREE(session, data);
            return i;
        }
        
        _libssh2_debug(session, LIBSSH2_DBG_TRANS, "Blocking until packet becomes available to burn");
        *state = libssh2_NB_state_created;
    }
        
    while (session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
        if ((ret = libssh2_packet_read(session)) == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
        else if (ret < 0) {
            *state = libssh2_NB_state_idle;
            return ret;
        }
        else if (ret == 0) {
            /* FIXME: this might busyloop */
            continue;
        }
        
        /* Be lazy, let packet_ask pull it out of the brigade */
        if (0 == libssh2_packet_ask_ex(session, ret, &data, &data_len, 0, NULL, 0, 0)) {
            /* Smoke 'em if you got 'em */
            LIBSSH2_FREE(session, data);
            *state = libssh2_NB_state_idle;
            return ret;
        }
    }
    
    /* Only reached if the socket died */
    return -1;
}
/* }}} */

/*
 * {{{ libssh2_packet_requirev
 *
 * Loops libssh2_packet_read() until one of a list of packet types requested is
 * available
 * SSH_DISCONNECT or a SOCKET_DISCONNECTED will cause a bailout
 * packet_types is a null terminated list of packet_type numbers
 */

int libssh2_packet_requirev_ex(LIBSSH2_SESSION *session, const unsigned char *packet_types, unsigned char **data,
                               unsigned long *data_len, unsigned long match_ofs, const unsigned char *match_buf,
                               unsigned long match_len, packet_requirev_state_t *state)
{
    if (libssh2_packet_askv_ex(session, packet_types, data, data_len, match_ofs, match_buf, match_len, 0) == 0) {
        /* One of the packets listed was available in the packet
           brigade */
        state->start = 0;
        return 0;
    }
    
    if (state->start == 0) {
        state->start = time(NULL);
    }
    
    while (session->socket_state != LIBSSH2_SOCKET_DISCONNECTED) {
        int ret = libssh2_packet_read(session);
        if ((ret < 0) && (ret != PACKET_EAGAIN)) {
            state->start = 0;
            return ret;
        }
        if (ret <= 0) {
            long left = LIBSSH2_READ_TIMEOUT - (time(NULL) - state->start);
            
            if ((left <= 0) || (libssh2_waitsocket(session, left) <= 0 )) {
                state->start = 0;
                return PACKET_TIMEOUT;
            }
            else if (ret == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            }
        }
        
        if (strchr((char *)packet_types, ret)) {
            /* Be lazy, let packet_ask pull it out of the brigade */
            return libssh2_packet_askv_ex(session, packet_types, data, data_len, match_ofs, match_buf, match_len, 0);
        }
    }
    
    /* Only reached if the socket died */
    state->start = 0;
    return -1;
}
/* }}} */
