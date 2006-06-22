/* Copyright (c) 2004-2006, Sara Golemon <sarag@libssh2.org>
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
#ifndef WIN32
#include <unistd.h>
#endif
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_POLL
# include <sys/poll.h>
#else
# ifdef HAVE_SELECT
#  ifdef HAVE_SYS_SELECT_H
#   include <sys/select.h>
#  else
#   include <sys/time.h>
#   include <sys/types.h>
#  endif
# endif
#endif

/* {{{ libssh2_packet_queue_listener
 * Queue a connection request for a listener
 */
inline int libssh2_packet_queue_listener(LIBSSH2_SESSION *session, unsigned char *data, unsigned long datalen)
{
	/* Look for a matching listener */
	unsigned char *s = data + (sizeof("forwarded-tcpip") - 1) + 5;
	unsigned long packet_len = 17 + (sizeof("Forward not requested") - 1);
	unsigned char *p, packet[17 + (sizeof("Forward not requested") - 1)];
					/* packet_type(1) + channel(4) + reason(4) + descr(4) + lang(4) */
	LIBSSH2_LISTENER *l = session->listeners;
	char failure_code = 1; /* SSH_OPEN_ADMINISTRATIVELY_PROHIBITED */
	unsigned long sender_channel, initial_window_size, packet_size;
	unsigned char *host, *shost;
	unsigned long port, sport, host_len, shost_len;

	sender_channel = libssh2_ntohu32(s);		s += 4;

	initial_window_size = libssh2_ntohu32(s);	s += 4;
	packet_size = libssh2_ntohu32(s);			s += 4;

	host_len = libssh2_ntohu32(s);				s += 4;
	host = s;									s += host_len;
	port = libssh2_ntohu32(s);					s += 4;

	shost_len = libssh2_ntohu32(s);				s += 4;
	shost = s;									s += shost_len;
	sport = libssh2_ntohu32(s);					s += 4;

#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "Remote received connection from %s:%ld to %s:%ld", shost, sport, host, port);
#endif
	while (l) {
		if ((l->port == port) &&
			(strlen(l->host) == host_len) &&
			(memcmp(l->host, host, host_len) == 0)) {
			/* This is our listener */
			LIBSSH2_CHANNEL *channel, *last_queued = l->queue;

			if (l->queue_maxsize &&
				(l->queue_maxsize <= l->queue_size)) {
				/* Queue is full */
				failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "Listener queue full, ignoring");
#endif
				break;
			}

			channel = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_CHANNEL));
			if (!channel) {
				libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a channel for new connection", 0);
				failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
				break;
			}
			memset(channel, 0, sizeof(LIBSSH2_CHANNEL));

			channel->session = session;
			channel->channel_type_len = sizeof("forwarded-tcpip") - 1;
			channel->channel_type = LIBSSH2_ALLOC(session, channel->channel_type_len + 1);
			if (!channel->channel_type) {
				libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a channel for new connection", 0);
				LIBSSH2_FREE(session, channel);
				failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
				break;
			}
			memcpy(channel->channel_type, "forwarded-tcpip", channel->channel_type_len + 1);

			channel->remote.id = sender_channel;
			channel->remote.window_size_initial = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
			channel->remote.window_size = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
			channel->remote.packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT;

			channel->local.id = libssh2_channel_nextid(session);
			channel->local.window_size_initial = initial_window_size;
			channel->local.window_size = initial_window_size;
			channel->local.packet_size = packet_size;

#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "Connection queued: channel %lu/%lu win %lu/%lu packet %lu/%lu",
														channel->local.id, channel->remote.id,
														channel->local.window_size, channel->remote.window_size,
														channel->local.packet_size, channel->remote.packet_size);
#endif

			p = packet;
			*(p++) = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
			libssh2_htonu32(p, channel->remote.id);						p += 4;
			libssh2_htonu32(p, channel->local.id);						p += 4;
			libssh2_htonu32(p, channel->remote.window_size_initial);	p += 4;
			libssh2_htonu32(p, channel->remote.packet_size);			p += 4;

			if (libssh2_packet_write(session, packet, 17)) {
				libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send channel open confirmation", 0);
				return -1;
			}

			/* Link the channel into the end of the queue list */

			if (!last_queued) {
				l->queue = channel;
				return 0;
			}

			while (last_queued->next) last_queued = last_queued->next;

			last_queued->next = channel;
			channel->prev = last_queued;

			l->queue_size++;

			return 0;
		}

		l = l->next;
	}

	/* We're not listening to you */
	{

		p = packet;
		*(p++) = SSH_MSG_CHANNEL_OPEN_FAILURE;
		libssh2_htonu32(p, sender_channel);		p += 4;
		libssh2_htonu32(p, failure_code);		p += 4;
		libssh2_htonu32(p, sizeof("Forward not requested") - 1);	p += 4;
		memcpy(s, "Forward not requested", sizeof("Forward not requested") - 1);	p += sizeof("Forward not requested") - 1;
		libssh2_htonu32(p, 0);

		if (libssh2_packet_write(session, packet, packet_len)) {
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send open failure", 0);
			return -1;
		}
		return 0;
	}
}
/* }}} */

/* {{{ libssh2_packet_x11_open
 * Accept a forwarded X11 connection
 */
inline int libssh2_packet_x11_open(LIBSSH2_SESSION *session, unsigned char *data, unsigned long datalen)
{
	int failure_code = 2; /* SSH_OPEN_CONNECT_FAILED */
	unsigned char *s = data + (sizeof("x11") - 1) + 5;
	unsigned long packet_len = 17 + (sizeof("X11 Forward Unavailable") - 1);
	unsigned char *p, packet[17 + (sizeof("X11 Forward Unavailable") - 1)];
					/* packet_type(1) + channel(4) + reason(4) + descr(4) + lang(4) */
	LIBSSH2_CHANNEL *channel;
	unsigned long sender_channel, initial_window_size, packet_size;
	unsigned char *shost;
	unsigned long sport, shost_len;

	sender_channel = libssh2_ntohu32(s);			s += 4;
	initial_window_size = libssh2_ntohu32(s);		s += 4;
	packet_size = libssh2_ntohu32(s);				s += 4;
	shost_len = libssh2_ntohu32(s);					s += 4;
	shost = s;										s += shost_len;
	sport = libssh2_ntohu32(s);						s += 4;

#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "X11 Connection Received from %s:%ld on channel %lu", shost, sport, sender_channel);
#endif
	if (session->x11) {
		channel = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_CHANNEL));
		if (!channel) {
			libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a channel for new connection", 0);
			failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
			goto x11_exit;
		}
		memset(channel, 0, sizeof(LIBSSH2_CHANNEL));

		channel->session = session;
		channel->channel_type_len = sizeof("x11") - 1;
		channel->channel_type = LIBSSH2_ALLOC(session, channel->channel_type_len + 1);
		if (!channel->channel_type) {
			libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a channel for new connection", 0);
			LIBSSH2_FREE(session, channel);
			failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
			goto x11_exit;
		}
		memcpy(channel->channel_type, "x11", channel->channel_type_len + 1);

		channel->remote.id = sender_channel;
		channel->remote.window_size_initial = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
		channel->remote.window_size = LIBSSH2_CHANNEL_WINDOW_DEFAULT;
		channel->remote.packet_size = LIBSSH2_CHANNEL_PACKET_DEFAULT;

		channel->local.id = libssh2_channel_nextid(session);
		channel->local.window_size_initial = initial_window_size;
		channel->local.window_size = initial_window_size;
		channel->local.packet_size = packet_size;

#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "X11 Connection established: channel %lu/%lu win %lu/%lu packet %lu/%lu",
														channel->local.id, channel->remote.id,
														channel->local.window_size, channel->remote.window_size,
														channel->local.packet_size, channel->remote.packet_size);
#endif
		p = packet;
		*(p++) = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
		libssh2_htonu32(p, channel->remote.id);						p += 4;
		libssh2_htonu32(p, channel->local.id);						p += 4;
		libssh2_htonu32(p, channel->remote.window_size_initial);	p += 4;
		libssh2_htonu32(p, channel->remote.packet_size);			p += 4;

		if (libssh2_packet_write(session, packet, 17)) {
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send channel open confirmation", 0);
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

		/* Pass control to the callback, they may turn right around and free the channel, or actually use it */
		LIBSSH2_X11_OPEN(channel, shost, sport);

		return 0;
	} else {
		failure_code = 4; /* SSH_OPEN_RESOURCE_SHORTAGE */
	}

 x11_exit:
	p = packet;
	*(p++) = SSH_MSG_CHANNEL_OPEN_FAILURE;
	libssh2_htonu32(p, sender_channel);				p += 4;
	libssh2_htonu32(p, failure_code);				p += 4;
	libssh2_htonu32(p, sizeof("X11 Forward Unavailable") - 1);		p += 4;
	memcpy(s, "X11 Forward Unavailable", sizeof("X11 Forward Unavailable") - 1); p += sizeof("X11 Forward Unavailable") - 1;
	libssh2_htonu32(p, 0);

	if (libssh2_packet_write(session, packet, packet_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send open failure", 0);
		return -1;
	}
	return 0;
}
/* }}} */

/* {{{ libssh2_packet_new
 * Create a new packet and attach it to the brigade
 */
static int libssh2_packet_add(LIBSSH2_SESSION *session, unsigned char *data, size_t datalen, int macstate)
{
	LIBSSH2_PACKET *packet;
	unsigned long data_head = 0;

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Packet type %d received, length=%d", (int)data[0], (int)datalen);
#endif
	if (macstate == LIBSSH2_MAC_INVALID) {
		if (session->macerror) {
			if (LIBSSH2_MACERROR(session, data, datalen) == 0) {
				/* Calling app has given the OK, Process it anyway */
				macstate = LIBSSH2_MAC_CONFIRMED;
			} else {
				libssh2_error(session, LIBSSH2_ERROR_INVALID_MAC, "Invalid Message Authentication Code received", 0);
				if (session->ssh_msg_disconnect) {
					LIBSSH2_DISCONNECT(session, SSH_DISCONNECT_MAC_ERROR, "Invalid MAC received", sizeof("Invalid MAC received") - 1, "", 0);
				}
				return -1;
			}
		} else {
			libssh2_error(session, LIBSSH2_ERROR_INVALID_MAC, "Invalid Message Authentication Code received", 0);
			if (session->ssh_msg_disconnect) {
				LIBSSH2_DISCONNECT(session, SSH_DISCONNECT_MAC_ERROR, "Invalid MAC received", sizeof("Invalid MAC received") - 1, "", 0);
			}
			return -1;
		}
	}

	/* A couple exceptions to the packet adding rule: */
	switch (data[0]) {
		case SSH_MSG_DISCONNECT:
		{
			char *message, *language;
			int reason, message_len, language_len;

			reason = libssh2_ntohu32(data + 1);
			message_len = libssh2_ntohu32(data + 5);
			message = data + 9; /* packet_type(1) + reason(4) + message_len(4) */
			language_len = libssh2_ntohu32(data + 9 + message_len);
			/* This is where we hack on the data a little,
			 * Use the MSB of language_len to to a terminating NULL (In all liklihood it is already)
			 * Shift the language tag back a byte (In all likelihood it's zero length anyway
			 * Store a NULL in the last byte of the packet to terminate the language string
			 * With the lengths passed this isn't *REALLY* necessary, but it's "kind"
			 */
			message[message_len] = '\0';
			language = data + 9 + message_len + 3;
			if (language_len) {
				memcpy(language, language + 1, language_len);
			}
			language[language_len] = '\0';

			if (session->ssh_msg_disconnect) {
				LIBSSH2_DISCONNECT(session, reason, message, message_len, language, language_len);
			}
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Disconnect(%d): %s(%s)", reason, message, language);
#endif
			LIBSSH2_FREE(session, data);
			session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
			return -1;
		}
			break;
		case SSH_MSG_IGNORE:
			/* As with disconnect, back it up one and add a trailing NULL */
			memcpy(data + 4, data + 5, datalen - 5);
			data[datalen] = '\0';
			if (session->ssh_msg_ignore) {
				LIBSSH2_IGNORE(session, data + 4, datalen - 5);
			}
			LIBSSH2_FREE(session, data);
			return 0;
			break;
		case SSH_MSG_DEBUG:
		{
			int always_display = data[0];
			char *message, *language;
			int message_len, language_len;

			message_len = libssh2_ntohu32(data + 2);
			message = data + 6; /* packet_type(1) + display(1) + message_len(4) */
			language_len = libssh2_ntohu32(data + 6 + message_len);
			/* This is where we hack on the data a little,
			 * Use the MSB of language_len to to a terminating NULL (In all liklihood it is already)
			 * Shift the language tag back a byte (In all likelihood it's zero length anyway
			 * Store a NULL in the last byte of the packet to terminate the language string
			 * With the lengths passed this isn't *REALLY* necessary, but it's "kind"
			 */
			message[message_len] = '\0';
			language = data + 6 + message_len + 3;
			if (language_len) {
				memcpy(language, language + 1, language_len);
			}
			language[language_len] = '\0';

			if (session->ssh_msg_debug) {
				LIBSSH2_DEBUG(session, always_display, message, message_len, language, language_len);
			}
#ifdef LIBSSH2_DEBUG_TRANSPORT
	/* _libssh2_debug will actually truncate this for us so that it's not an inordinate about of data */
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Debug Packet: %s", message);
#endif
			LIBSSH2_FREE(session, data);
			return 0;
		}
			break;
		case SSH_MSG_CHANNEL_EXTENDED_DATA:
			data_head += 4; /* streamid(4) */
		case SSH_MSG_CHANNEL_DATA:
			data_head += 9; /* packet_type(1) + channelno(4) + datalen(4) */
			{
				LIBSSH2_CHANNEL *channel = libssh2_channel_locate(session, libssh2_ntohu32(data + 1));

				if (!channel) {
					libssh2_error(session, LIBSSH2_ERROR_CHANNEL_UNKNOWN, "Packet received for unknown channel, ignoring", 0);
					LIBSSH2_FREE(session, data);
					return 0;
				}
#ifdef LIBSSH2_DEBUG_CONNECTION
{
	unsigned long stream_id = 0;

	if (data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA) {
		stream_id = libssh2_ntohu32(data + 5);
	}

	_libssh2_debug(session, LIBSSH2_DBG_CONN, "%d bytes received for channel %lu/%lu stream #%lu", (int)(datalen - data_head), channel->local.id, channel->remote.id, stream_id);
}
#endif
				if ((channel->remote.extended_data_ignore_mode == LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE) && (data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA)) {
					/* Pretend we didn't receive this */
					LIBSSH2_FREE(session, data);

#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "Ignoring extended data and refunding %d bytes", (int)(datalen - 13));
#endif
					/* Adjust the window based on the block we just freed */
					libssh2_channel_receive_window_adjust(channel, datalen - 13, 0);

					return 0;
				}

				/* REMEMBER! remote means remote as source of data, NOT remote window! */
				if (channel->remote.packet_size < (datalen - data_head)) {
					/* Spec says we MAY ignore bytes sent beyond packet_size */
					libssh2_error(session, LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED, "Packet contains more data than we offered to receive, truncating", 0);
					datalen = channel->remote.packet_size + data_head;
				}
				if (channel->remote.window_size <= 0) {
					/* Spec says we MAY ignore bytes sent beyond window_size */
					libssh2_error(session, LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED, "The current receive window is full, data ignored", 0);
					LIBSSH2_FREE(session, data);
					return 0;
				}
				/* Reset EOF status */
				channel->remote.eof = 0;

				if ((datalen - data_head) > channel->remote.window_size) {
					libssh2_error(session, LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED, "Remote sent more data than current window allows, truncating", 0);
					datalen = channel->remote.window_size + data_head;
				} else {
					/* Now that we've received it, shrink our window */
					channel->remote.window_size -= datalen - data_head;
				}
			}
			break;
		case SSH_MSG_CHANNEL_EOF:
			{
				LIBSSH2_CHANNEL *channel = libssh2_channel_locate(session, libssh2_ntohu32(data + 1));

				if (!channel) {
					/* We may have freed already, just quietly ignore this... */
					LIBSSH2_FREE(session, data);
					return 0;
				}

#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "EOF received for channel %lu/%lu", channel->local.id, channel->remote.id);
#endif
				channel->remote.eof = 1;

				LIBSSH2_FREE(session, data);
				return 0;
			}
			break;
	    case SSH_MSG_CHANNEL_REQUEST:
		    {
				if (libssh2_ntohu32(data+5) == sizeof("exit-status") - 1
					&& !memcmp("exit-status", data + 9, sizeof("exit-status") - 1)) {

					/* we've got "exit-status" packet. Set the session value */
					LIBSSH2_CHANNEL *channel = libssh2_channel_locate(session, libssh2_ntohu32(data+1));

					if (channel) {
						channel->exit_status = libssh2_ntohu32(data + 9 + sizeof("exit-status"));
#ifdef LIBSSH2_DEBUG_CONNECTION
						_libssh2_debug(session, LIBSSH2_DBG_CONN, "Exit status %lu received for channel %lu/%lu", channel->exit_status, channel->local.id, channel->remote.id);
#endif
					}

					LIBSSH2_FREE(session, data);
					return 0;
				}
			}
			break;
		case SSH_MSG_CHANNEL_CLOSE:
			{
				LIBSSH2_CHANNEL *channel = libssh2_channel_locate(session, libssh2_ntohu32(data + 1));

				if (!channel) {
					/* We may have freed already, just quietly ignore this... */
					LIBSSH2_FREE(session, data);
					return 0;
				}
#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "Close received for channel %lu/%lu", channel->local.id, channel->remote.id);
#endif

				channel->remote.close = 1;
				/* TODO: Add a callback for this */

				LIBSSH2_FREE(session, data);
				return 0;
			}
			break;
		case SSH_MSG_CHANNEL_OPEN:
			if ((datalen >= (sizeof("forwarded-tcpip") + 4)) &&
				((sizeof("forwarded-tcpip")-1) == libssh2_ntohu32(data + 1)) &&
				(memcmp(data + 5, "forwarded-tcpip", sizeof("forwarded-tcpip") - 1) == 0)) {
				int retval = libssh2_packet_queue_listener(session, data, datalen);

				LIBSSH2_FREE(session, data);
				return retval;
			}
			if ((datalen >= (sizeof("x11") + 4)) &&
				((sizeof("x11")-1) == libssh2_ntohu32(data + 1)) &&
				(memcmp(data + 5, "x11", sizeof("x11") - 1) == 0)) {
				int retval = libssh2_packet_x11_open(session, data, datalen);

				LIBSSH2_FREE(session, data);
				return retval;
			}
			break;
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			{
				LIBSSH2_CHANNEL *channel = libssh2_channel_locate(session, libssh2_ntohu32(data + 1));
				unsigned long bytestoadd = libssh2_ntohu32(data + 5);

				if (channel && bytestoadd) {
					channel->local.window_size += bytestoadd;
				}
#ifdef LIBSSH2_DEBUG_CONNECTION
	_libssh2_debug(session, LIBSSH2_DBG_CONN, "Window adjust received for channel %lu/%lu, adding %lu bytes, new window_size=%lu", channel->local.id, channel->remote.id, bytestoadd, channel->local.window_size);
#endif

				LIBSSH2_FREE(session, data);
				return 0;
			}
			break;
	}

	packet = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_PACKET));
	memset(packet, 0, sizeof(LIBSSH2_PACKET));

	packet->data = data;
	packet->data_len = datalen;
	packet->data_head = data_head;
	packet->mac = macstate;
	packet->brigade = &session->packets;
	packet->next = NULL;

	if (session->packets.tail) {
		packet->prev = session->packets.tail;
		packet->prev->next = packet;
		session->packets.tail = packet;
	} else {
		session->packets.head = packet;
		session->packets.tail = packet;
		packet->prev = NULL;
	}

	if (data[0] == SSH_MSG_KEXINIT && !(session->state & LIBSSH2_STATE_EXCHANGING_KEYS)) {
		/* Remote wants new keys
		 * Well, it's already in the brigade,
		 * let's just call back into ourselves
		 */
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Renegotiating Keys");
#endif
		libssh2_kex_exchange(session, 1);
		/* If there was a key reexchange failure, let's just hope we didn't send NEWKEYS yet, otherwise remote will drop us like a rock */
	}

	return 0;
}
/* }}} */

/* {{{ libssh2_blocking_read
 * Force a blocking read, regardless of socket settings
 */
static int libssh2_blocking_read(LIBSSH2_SESSION *session, unsigned char *buf, size_t count)
{
	size_t bytes_read = 0;
#if !defined(HAVE_POLL) && !defined(HAVE_SELECT)
	int polls = 0;
#endif

#ifndef WIN32
	fcntl(session->socket_fd, F_SETFL, 0);
#else
	{
		u_long block = FALSE;
		ioctlsocket(session->socket_fd, FIONBIO, &block);
	}
#endif

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Blocking read: %d bytes", (int)count);
#endif

	while (bytes_read < count) {
		int ret;

		ret = recv(session->socket_fd, buf + bytes_read, count - bytes_read, LIBSSH2_SOCKET_RECV_FLAGS(session));
		if (ret < 0) {
#ifdef WIN32
			switch (WSAGetLastError()) {
				case WSAEWOULDBLOCK:	errno = EAGAIN;		break;
				case WSAENOTSOCK:		errno = EBADF;		break;
				case WSAENOTCONN:
				case WSAECONNABORTED:	errno = ENOTCONN;	break;
				case WSAEINTR:			errno = EINTR;		break;
			}
#endif
			if (errno == EAGAIN) {
#ifdef HAVE_POLL
				struct pollfd read_socket;

				read_socket.fd = session->socket_fd;
				read_socket.events = POLLIN;

				if (poll(&read_socket, 1, 30000) <= 0) {
					return -1;
				}
#elif defined(HAVE_SELECT)
				fd_set read_socket;
				struct timeval timeout;

				FD_ZERO(&read_socket);
				FD_SET(session->socket_fd, &read_socket);

				timeout.tv_sec = 30;
				timeout.tv_usec = 0;

				if (select(session->socket_fd + 1, &read_socket, NULL, NULL, &timeout) <= 0) {
					return -1;
				}
#else
				if (polls++ > LIBSSH2_SOCKET_POLL_MAXLOOPS) {
					return -1;
				}
				usleep(LIBSSH2_SOCKET_POLL_UDELAY);
#endif /* POLL/SELECT/SLEEP */
				continue;
			}
			if (errno == EINTR) {
				continue;
			}
			if ((errno == EBADF) || (errno == EIO) || (errno == ENOTCONN)) {
				session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
			}
			return -1;
		}
		if (ret == 0) continue;

		bytes_read += ret;
	}

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Blocking read: %d bytes actually read", (int)bytes_read);
#endif

	return bytes_read;
}
/* }}} */

/* {{{ libssh2_packet_read
 * Collect a packet into the input brigade
 * block only controls whether or not to wait for a packet to start,
 * Once a packet starts, libssh2 will block until it is complete
 * Returns packet type added to input brigade (0 if nothing added), or -1 on failure
 */
int libssh2_packet_read(LIBSSH2_SESSION *session, int should_block)
{
	int packet_type = -1;

	if (session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
		return 0;
	}

#ifndef WIN32
	fcntl(session->socket_fd, F_SETFL, O_NONBLOCK);
#else
	{
		u_long non_block = TRUE;
		ioctlsocket(session->socket_fd, FIONBIO, &non_block);
	}
#endif

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Checking for packet: will%s block", should_block ? "" : " not");
#endif
	if (session->state & LIBSSH2_STATE_NEWKEYS) {
		/* Temporary Buffer
		 * The largest blocksize (currently) is 32, the largest MAC (currently) is 20
		 */
		unsigned char block[2 * 32], *payload, *s, tmp[6];
		long read_len;
		unsigned long blocksize = session->remote.crypt->blocksize;
		unsigned long packet_len, payload_len;
		int padding_len;
		int macstate;
		int free_payload = 1;
		/* Safely ignored in CUSTOM cipher mode */
		EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)session->remote.crypt_abstract;

		/* Note: If we add any cipher with a blocksize less than 6 we'll need to get more creative with this
		 * For now, all blocksize sizes are 8+
		 */
		if (should_block) {
			read_len = libssh2_blocking_read(session, block, blocksize);
		} else {
			read_len = recv(session->socket_fd, block, 1, LIBSSH2_SOCKET_RECV_FLAGS(session));
			if (read_len <= 0) {
				return 0;
			}
			read_len += libssh2_blocking_read(session, block + read_len, blocksize - read_len);
		}
		if (read_len < blocksize) {
			return (session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) ? 0 : -1;
		}

		if (session->remote.crypt->flags & LIBSSH2_CRYPT_METHOD_FLAG_EVP) {
			EVP_Cipher(ctx, block + blocksize, block, blocksize);
			memcpy(block, block + blocksize, blocksize);
		} else {
			if (session->remote.crypt->crypt(session, block, &session->remote.crypt_abstract)) {
				libssh2_error(session, LIBSSH2_ERROR_DECRYPT, "Error decrypting packet preamble", 0);
				return -1;
			}
		}

		packet_len = libssh2_ntohu32(block);
		padding_len = block[4];
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Processing packet %lu bytes long (with %lu bytes padding)", packet_len, padding_len);
#endif
		memcpy(tmp, block, 5); /* Use this for MAC later */

		payload_len = packet_len - 1; /* padding_len(1) */
		/* Sanity Check */
		if ((payload_len > LIBSSH2_PACKET_MAXPAYLOAD) ||
			((packet_len + 4) % blocksize)) {
			/* If something goes horribly wrong during the decryption phase, just bailout and die gracefully */
			session->socket_state = LIBSSH2_SOCKET_DISCONNECTED;
			libssh2_error(session, LIBSSH2_ERROR_PROTO, "Fatal protocol error, invalid payload size", 0);
			return -1;
		}

		s = payload = LIBSSH2_ALLOC(session, payload_len);
		memcpy(s, block + 5, blocksize - 5);
		s += blocksize - 5;

		while ((s - payload) < payload_len) {
			read_len = libssh2_blocking_read(session, block, blocksize);
			if (read_len < blocksize) {
				LIBSSH2_FREE(session, payload);
				return -1;
			}
			if (session->remote.crypt->flags & LIBSSH2_CRYPT_METHOD_FLAG_EVP) {
				EVP_Cipher(ctx, block + blocksize, block, blocksize);
				memcpy(s, block + blocksize, blocksize);
			} else {
				if (session->remote.crypt->crypt(session, block, &session->remote.crypt_abstract)) {
					libssh2_error(session, LIBSSH2_ERROR_DECRYPT, "Error decrypting packet preamble", 0);
					LIBSSH2_FREE(session, payload);
					return -1;
				}
				memcpy(s, block, blocksize);
			}

			s += blocksize;
		}

		read_len = libssh2_blocking_read(session, block, session->remote.mac->mac_len);
		if (read_len < session->remote.mac->mac_len) {
			LIBSSH2_FREE(session, payload);
			return -1;
		}

		/* Calculate MAC hash */
 		session->remote.mac->hash(session, block + session->remote.mac->mac_len, session->remote.seqno, tmp, 5, payload, payload_len, &session->remote.mac_abstract);

		macstate =  (strncmp(block, block + session->remote.mac->mac_len, session->remote.mac->mac_len) == 0) ? LIBSSH2_MAC_CONFIRMED : LIBSSH2_MAC_INVALID;

		session->remote.seqno++;

		/* Ignore padding */
		payload_len -= padding_len;

		if (session->remote.comp &&
			strcmp(session->remote.comp->name, "none")) {
			/* Decompress */
			unsigned char *data;
			unsigned long data_len;

			if (session->remote.comp->comp(session, 0, &data, &data_len, LIBSSH2_PACKET_MAXDECOMP, &free_payload, payload, payload_len, &session->remote.comp_abstract)) {
				LIBSSH2_FREE(session, payload);
				return -1;
			}
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Payload decompressed: %lu bytes(compressed) to %lu bytes(uncompressed)", data_len, payload_len);
#endif
			if (free_payload) {
				LIBSSH2_FREE(session, payload);
				payload = data;
				payload_len = data_len;
			} else {
				if (data == payload) {
					/* It's not to be freed, because the compression layer reused payload,
					 * So let's do the same!
					 */
					payload_len = data_len;
				} else {
					/* No comp_method actually lets this happen, but let's prepare for the future */

					LIBSSH2_FREE(session, payload);

					/* We need a freeable struct otherwise the brigade won't know what to do with it */
					payload = LIBSSH2_ALLOC(session, data_len);
					if (!payload) {
						libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for copy of uncompressed data", 0);
						return -1;
					}
					memcpy(payload, data, data_len);
					payload_len = data_len;
				}
			}
		}

		packet_type = payload[0];
		libssh2_packet_add(session, payload, payload_len, macstate);

	} else { /* No cipher active */
		unsigned char *payload;
		unsigned char buf[24];
		unsigned long buf_len, payload_len;
		unsigned long packet_length;
		unsigned long padding_length;

		if (should_block) {
			buf_len = libssh2_blocking_read(session, buf, 5);
		} else {
			buf_len = recv(session->socket_fd, buf, 1, LIBSSH2_SOCKET_RECV_FLAGS(session));
			if (buf_len <= 0) {
				return 0;
			}
			buf_len += libssh2_blocking_read(session, buf, 5 - buf_len);
		}
		if (buf_len < 5) {
			/* Something bad happened */
			return -1;
		}
		packet_length = libssh2_ntohu32(buf);
		padding_length = buf[4];
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Processing plaintext packet %lu bytes long (with %lu bytes padding)", packet_length, padding_length);
#endif

		payload_len = packet_length - padding_length - 1; /* padding_length(1) */
		payload = LIBSSH2_ALLOC(session, payload_len);
		if (!payload) {
			libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for copy of plaintext data", 0);
			return -1;
		}

		if (libssh2_blocking_read(session, payload, payload_len) < payload_len) {
			return (session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) ? 0 : -1;
		}
		while (padding_length) {
			int l;
			/* Flush padding */
			l = libssh2_blocking_read(session, buf, padding_length);
			if (l > 0)
				padding_length -= l;
			else
				break;
		}

		packet_type = payload[0];

		/* MACs don't exist in non-encrypted mode */
		libssh2_packet_add(session, payload, payload_len, LIBSSH2_MAC_CONFIRMED);
		session->remote.seqno++;
	}
	return packet_type;
}
/* }}} */

/* {{{ libssh2_packet_ask
 * Scan the brigade for a matching packet type, optionally poll the socket for a packet first
 */
int libssh2_packet_ask_ex(LIBSSH2_SESSION *session, unsigned char packet_type, unsigned char **data, unsigned long *data_len,
													unsigned long match_ofs, const unsigned char *match_buf, unsigned long match_len, int poll_socket)
{
	LIBSSH2_PACKET *packet = session->packets.head;

	if (poll_socket) {
		if (libssh2_packet_read(session, 0) < 0) {
			return -1;
		}
	}
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Looking for packet of type: %d", (int)packet_type);
#endif
	while (packet) {
		if (packet->data[0] == packet_type &&
			(packet->data_len >= (match_ofs + match_len)) &&
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
 * Scan for any of a list of packet types in the brigade, optionally poll the socket for a packet first
 */
int libssh2_packet_askv_ex(LIBSSH2_SESSION *session, unsigned char *packet_types, unsigned char **data, unsigned long *data_len,
													 unsigned long match_ofs, const unsigned char *match_buf, unsigned long match_len, int poll_socket)
{
	int i, packet_types_len = strlen(packet_types);

	for(i = 0; i < packet_types_len; i++) {
		if (0 == libssh2_packet_ask_ex(session, packet_types[i], data, data_len, match_ofs, match_buf, match_len, i ? 0 : poll_socket)) {
			return 0;
		}
	}

	return -1;
}
/* }}} */

/* {{{ libssh2_packet_require
 * Loops libssh2_packet_read() until the packet requested is available
 * SSH_DISCONNECT or a SOCKET_DISCONNECTED will cause a bailout
 */
int libssh2_packet_require_ex(LIBSSH2_SESSION *session, unsigned char packet_type, unsigned char **data, unsigned long *data_len,
														unsigned long match_ofs, const unsigned char *match_buf, unsigned long match_len)
{
	if (libssh2_packet_ask_ex(session, packet_type, data, data_len, match_ofs, match_buf, match_len, 0) == 0) {
		/* A packet was available in the packet brigade */
		return 0;
	}

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Blocking until packet of type %d becomes available", (int)packet_type);
#endif
	while (session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
		int ret = libssh2_packet_read(session, 1);
		if (ret < 0) {
			return -1;
		}
		if (ret == 0) continue;

		if (packet_type == ret) {
			/* Be lazy, let packet_ask pull it out of the brigade */
			return libssh2_packet_ask_ex(session, packet_type, data, data_len, match_ofs, match_buf, match_len, 0);
		}
	}

	/* Only reached if the socket died */
	return -1;
}
/* }}} */

/* {{{ libssh2_packet_burn
 * Loops libssh2_packet_read() until any packet is available and promptly discards it
 * Used during KEX exchange to discard badly guessed KEX_INIT packets
 */
int libssh2_packet_burn(LIBSSH2_SESSION *session)
{
	unsigned char *data;
	unsigned long data_len;
	char all_packets[255];
	int i;
	for(i = 1; i < 256; i++) all_packets[i - 1] = i;

	if (libssh2_packet_askv_ex(session, all_packets, &data, &data_len, 0, NULL, 0, 0) == 0) {
		i = data[0];
		/* A packet was available in the packet brigade, burn it */
		LIBSSH2_FREE(session, data);
		return i;
	}

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Blocking until packet becomes available to burn");
#endif
	while (session->socket_state == LIBSSH2_SOCKET_CONNECTED) {
		int ret = libssh2_packet_read(session, 1);
		if (ret < 0) {
			return -1;
		}
		if (ret == 0) continue;

		/* Be lazy, let packet_ask pull it out of the brigade */
		if (0 == libssh2_packet_ask_ex(session, ret, &data, &data_len, 0, NULL, 0, 0)) {
			/* Smoke 'em if you got 'em */
			LIBSSH2_FREE(session, data);
			return ret;
		}
	}

	/* Only reached if the socket died */
	return -1;
}
/* }}} */

/* {{{ libssh2_packet_requirev
 * Loops libssh2_packet_read() until one of a list of packet types requested is available
 * SSH_DISCONNECT or a SOCKET_DISCONNECTED will cause a bailout
 * packet_types is a null terminated list of packet_type numbers
 */
int libssh2_packet_requirev_ex(LIBSSH2_SESSION *session, unsigned char *packet_types, unsigned char **data, unsigned long *data_len,
														 unsigned long match_ofs, const unsigned char *match_buf, unsigned long match_len)
{
	if (libssh2_packet_askv_ex(session, packet_types, data, data_len, match_ofs, match_buf, match_len, 0) == 0) {
		/* One of the packets listed was available in the packet brigade */
		return 0;
	}

	while (session->socket_state != LIBSSH2_SOCKET_DISCONNECTED) {
		int ret = libssh2_packet_read(session, 1);
		if (ret < 0) {
			return -1;
		}
		if (ret == 0) {
			continue;
		}

		if (strchr(packet_types, ret)) {
			/* Be lazy, let packet_ask pull it out of the brigade */
			return libssh2_packet_askv_ex(session, packet_types, data, data_len, match_ofs, match_buf, match_len, 0);
		}
	}

	/* Only reached if the socket died */
	return -1;
}
/* }}} */

/* {{{ libssh2_packet_write
 * Send a packet, encrypting it and adding a MAC code if necessary
 * Returns 0 on success, non-zero on failure
 */
int libssh2_packet_write(LIBSSH2_SESSION *session, unsigned char *data, unsigned long data_len)
{
	unsigned long packet_length = data_len + 1;
	unsigned long block_size = (session->state & LIBSSH2_STATE_NEWKEYS) ? session->local.crypt->blocksize : 8;
	/* At this point packet_length doesn't include the packet_len field itself */
	unsigned long padding_length;
	int free_data = 0;
	unsigned char buf[246]; /* 6 byte header plus max padding size(240) */

#ifdef LIBSSH2_DEBUG_TRANSPORT
{
	/* Show a hint of what's being sent */
	char excerpt[32];
	int ex_len = 0, db_ofs = 0;

	for (; ex_len < 24 && db_ofs < data_len; ex_len += 3, db_ofs++) snprintf(excerpt + ex_len, 4, "%02X ", data[db_ofs]);
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Sending packet type %d, length=%lu, %s", (int)data[0], data_len, excerpt);
}
#endif
	if ((session->state & LIBSSH2_STATE_NEWKEYS) &&
		strcmp(session->local.comp->name, "none")) {

		if (session->local.comp->comp(session, 1, &data, &data_len, LIBSSH2_PACKET_MAXCOMP, &free_data, data, data_len, &session->local.comp_abstract)) {
			return -1;
		}
#ifdef LIBSSH2_DEBUG_TRANSPORT
		_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Compressed payload to %lu bytes", data_len);
#endif
	}

#ifndef WIN32
	fcntl(session->socket_fd, F_SETFL, 0);
#else
	{
		u_long non_block = FALSE;
		ioctlsocket(session->socket_fd, FIONBIO, &non_block);
	}
#endif

	packet_length = data_len + 1; /* padding_length(1) -- MAC doesn't count -- Padding to be added soon */
	padding_length = block_size - ((packet_length + 4) % block_size);
	if (padding_length < 4) {
		padding_length += block_size;
	}
	/* TODO: Maybe add 1 or 2 times block_size to padding_length randomly -- shake things up a bit... */

	packet_length += padding_length;
	libssh2_htonu32(buf, packet_length);
	buf[4] = padding_length;
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Sending packet with total length %lu (%lu bytes padding)", packet_length, padding_length);
#endif

	if (session->state & LIBSSH2_STATE_NEWKEYS) {
		/* Encryption is in effect */
		unsigned char *encbuf, *s;
		int ret;

		/* Safely ignored in CUSTOM cipher mode */
		EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *)session->local.crypt_abstract;

		/* include packet_length(4) itself and room for the hash at the end */
		encbuf = LIBSSH2_ALLOC(session, 4 + packet_length + session->local.mac->mac_len);
		if (!encbuf) {
			libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate encryption buffer", 0);
			if (free_data) {
				LIBSSH2_FREE(session, data);
			}
			return -1;
		}

		/* Copy packet to encoding buffer */
		memcpy(encbuf, buf, 5);
		memcpy(encbuf + 5, data, data_len);
		RAND_bytes(encbuf + 5 + data_len, padding_length);
		if (free_data) {
			LIBSSH2_FREE(session, data);
		}

		/* Calculate MAC hash */
 		session->local.mac->hash(session, encbuf + 4 + packet_length , session->local.seqno, encbuf, 4 + packet_length, NULL, 0, &session->local.mac_abstract);

		/* Encrypt data */
		for(s = encbuf; (s - encbuf) < (4 + packet_length) ; s += session->local.crypt->blocksize) {
			if (session->local.crypt->flags & LIBSSH2_CRYPT_METHOD_FLAG_EVP) {
				EVP_Cipher(ctx, buf, s, session->local.crypt->blocksize);
				memcpy(s, buf, session->local.crypt->blocksize);
			} else {
				session->local.crypt->crypt(session, s, &session->local.crypt_abstract);
			}
		}

		session->local.seqno++;

		/* Send It */
		ret = ((4 + packet_length + session->local.mac->mac_len) == send(session->socket_fd, encbuf, 4 + packet_length + session->local.mac->mac_len, LIBSSH2_SOCKET_SEND_FLAGS(session))) ? 0 : -1;

		/* Cleanup environment */
		LIBSSH2_FREE(session, encbuf);

		return ret;
	} else { /* LIBSSH2_ENDPOINT_CRYPT_NONE */
		/* Simplified write for non-encrypted mode */
		struct iovec data_vector[3];

		/* Using vectors means we don't have to alloc a new buffer -- a byte saved is a byte earned
		 * No MAC during unencrypted phase
		 */
		data_vector[0].iov_base = buf;
		data_vector[0].iov_len = 5;
		data_vector[1].iov_base = (char*)data;
		data_vector[1].iov_len = data_len;
		data_vector[2].iov_base = buf + 5;
		data_vector[2].iov_len = padding_length;

		session->local.seqno++;

		/* Ignore this, it can't actually happen :) */
		if (free_data) {
			LIBSSH2_FREE(session, data);
		}

		return ((packet_length + 4) == writev(session->socket_fd, data_vector, 3)) ? 0 : 1;
	}
}
/* }}} */
