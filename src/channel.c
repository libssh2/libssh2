/* Copyright (c) 2004, Sara Golemon <sarag@users.sourceforge.net>
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
#include <unistd.h>

/* {{{ libssh2_channel_nextid
 * Determine the next channel ID we can use at our end
 */
static unsigned long libssh2_channel_nextid(LIBSSH2_SESSION *session)
{
	unsigned long id = session->next_channel;
	LIBSSH2_CHANNEL *channel;

	channel = session->channels.head;

	while (channel) {
		if (channel->local.id > id) {
			id = channel->local.id;
		}
		channel = channel->next;
	}

	/* This is a shortcut to avoid waiting for close packets on channels we've forgotten about,
	 * This *could* be a problem if we request and close 4 billion or so channels in too rapid succession
	 * for the remote end to respond, but the worst case scenario is that some data meant for another channel
	 * Gets picked up by the new one.... Pretty unlikely all told...
	 */
	session->next_channel = id + 1;

	return id;
}
/* }}} */

/* {{{ libssh2_channel_locate
 * Locate a channel pointer by number
 */
LIBSSH2_CHANNEL *libssh2_channel_locate(LIBSSH2_SESSION *session, unsigned long channel_id)
{
	LIBSSH2_CHANNEL *channel = session->channels.head;
	while (channel) {
		if (channel->local.id == channel_id) {
			return channel;
		}
		channel = channel->next;
	}

	return NULL;
}
/* }}} */

#define libssh2_channel_add(session, channel)	\
{	\
	if ((session)->channels.tail) {	\
		(session)->channels.tail->next = (channel);	\
		(channel)->prev = (session)->channels.tail;	\
	} else {	\
		(session)->channels.head = (channel);	\
		(channel)->prev = NULL;	\
	}	\
	(channel)->next = NULL;	\
	(session)->channels.tail = (channel);	\
	(channel)->session = (session);	\
}

/* {{{ libssh2_channel_open_session
 * Establish a generic session channel
 */
LIBSSH2_API LIBSSH2_CHANNEL *libssh2_channel_open_ex(LIBSSH2_SESSION *session, char *channel_type, int channel_type_len, int window_size, int packet_size,
																			   char *message, int message_len)
{
	LIBSSH2_CHANNEL *channel = NULL;
	unsigned long local_channel = libssh2_channel_nextid(session);
	unsigned char *s, *packet = NULL;
	unsigned long packet_len = channel_type_len + message_len + 17; /* packet_type(1) + channel_type_len(4) + sender_channel(4) + 
																	   window_size(4) + packet_size(4) */
	unsigned char *data = NULL;
	unsigned long data_len;
	int polls = 0;

	channel = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_CHANNEL));
	if (!channel) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate space for channel data", 0);
		return NULL;
	}
	memset(channel, 0, sizeof(LIBSSH2_CHANNEL));

	channel->channel_type_len	= channel_type_len;
	channel->channel_type		= LIBSSH2_ALLOC(session, channel_type_len);
	if (!channel->channel_type) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Failed allocating memory for channel type name", 0);
		LIBSSH2_FREE(session, channel);
		return NULL;
	}
	memcpy(channel->channel_type, channel_type, channel_type_len);

	/* REMEMBER: local as in locally sourced */
	channel->local.id					= local_channel;
	channel->remote.window_size 		= window_size;
	channel->remote.window_size_initial	= window_size;
	channel->remote.packet_size 		= packet_size;

	libssh2_channel_add(session, channel);

	s = packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate temporary space for packet", 0);
		return NULL;
	}
	*(s++) = SSH_MSG_CHANNEL_OPEN;
	libssh2_htonu32(s, channel_type_len);				s += 4;
	memcpy(s, channel_type, channel_type_len);			s += channel_type_len;

	libssh2_htonu32(s, local_channel);					s += 4;
	libssh2_htonu32(s, window_size);					s += 4;
	libssh2_htonu32(s, packet_size);					s += 4;

	if (message && message_len) {
		memcpy(s, message, message_len);				s += message_len;
	}

	if (libssh2_packet_write(session, packet, packet_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send channel-open request", 0);
		goto channel_error;
	}

	while (session->socket_state != LIBSSH2_SOCKET_DISCONNECTED) {
		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, &data, &data_len, 1, packet + 5 + channel_type_len, 4, 1) == 0) {
			/* YAY! You like me! */
			break;
		}
		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_OPEN_FAILURE, &data, &data_len, 1, packet + 5 + channel_type_len, 4, 0) == 0) {
			/* But! Dear! I thought we had something! */

			/* TODO: provide reason code and description */
			libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE, "Channel open failure", 0);
			goto channel_error;
		}
		usleep(LIBSSH2_SOCKET_POLL_UDELAY);
		if (polls++ > LIBSSH2_SOCKET_POLL_MAXLOOPS) {
			/* Give up waiting */
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT, "Timed out waiting for response", 0);
			goto channel_error;
		}
	}

	channel->remote.id					= libssh2_ntohu32(data + 5);
	channel->local.window_size			= libssh2_ntohu32(data + 9);
	channel->local.window_size_initial	= libssh2_ntohu32(data + 9);
	channel->local.packet_size			= libssh2_ntohu32(data + 13);

	LIBSSH2_FREE(session, packet);
	LIBSSH2_FREE(session, data);

	return channel;

 channel_error:

	if (data) {
		LIBSSH2_FREE(session, data);
	}
	if (packet) {
		LIBSSH2_FREE(session, packet);
	}
	if (channel) {
		unsigned char channel_id[4];
		LIBSSH2_FREE(session, channel->channel_type);

		if (channel->next) {
			channel->next->prev = channel->prev;
		}
		if (channel->prev) {
			channel->prev->next = channel->next;
		}
		if (session->channels.head == channel) {
			session->channels.head = channel->next;
		}
		if (session->channels.tail == channel) {
			session->channels.tail = channel->prev;
		}

		/* Clear out packets meant for this channel */
		libssh2_htonu32(channel_id, channel->local.id);
		while  ((libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_DATA, 		  &data, &data_len, 1, channel_id, 4, 1) >= 0) ||
				(libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_EXTENDED_DATA, &data, &data_len, 1, channel_id, 4, 1) >= 0)) {
			LIBSSH2_FREE(session, data);
		}

		LIBSSH2_FREE(session, channel);
	}

	return NULL;
}
/* }}} */

/* {{{ libssh2_channel_direct_tcpip_ex
 * Tunnel TCP/IP connect through the SSH session to direct host/port
 */
LIBSSH2_API LIBSSH2_CHANNEL *libssh2_channel_direct_tcpip_ex(LIBSSH2_SESSION *session, char *host, int port, char *shost, int sport)
{
	LIBSSH2_CHANNEL *channel;
	unsigned char *message, *s;
	unsigned long host_len = strlen(host), shost_len = strlen(shost);
	unsigned long message_len = host_len + shost_len + 16; /* host_len(4) + port(4) + shost_len(4) + sport(4) */

	s = message = LIBSSH2_ALLOC(session, message_len);
	if (!message) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for direct-tcpip connection", 0);
		return NULL;
	}
	libssh2_htonu32(s, host_len);					s += 4;
	memcpy(s, host, host_len);						s += host_len;
	libssh2_htonu32(s, port);						s += 4;

	libssh2_htonu32(s, shost_len);					s += 4;
	memcpy(s, shost, shost_len);					s += shost_len;
	libssh2_htonu32(s, sport);						s += 4;

	channel = libssh2_channel_open_ex(session, "direct-tcpip", sizeof("direct-tcpip") - 1, LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT, message, message_len);
	LIBSSH2_FREE(session, message);

	return channel;
}
/* }}} */

/* {{{ libssh2_channel_setenv_ex
 * Set an environment variable prior to requesting a shell/program/subsystem
 */
LIBSSH2_API int libssh2_channel_setenv_ex(LIBSSH2_CHANNEL *channel, char *varname, int varname_len, char *value, int value_len)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char *s, *packet;
	unsigned long packet_len = varname_len + value_len + 21; /* packet_type(1) + channel_id(4) + request_len(4) + request(3)"env" + 
																want_reply(1) + varname_len(4) + value_len(4) */

	s = packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memeory for setenv packet", 0);
		return -1;
	}

	*(s++) = SSH_MSG_CHANNEL_REQUEST;
	libssh2_htonu32(s, channel->remote.id);				s += 4;
	libssh2_htonu32(s, sizeof("env") - 1);				s += 4;
	memcpy(s, "env", sizeof("env") - 1);				s += sizeof("env") - 1;

	*(s++) = 0xFF;

	libssh2_htonu32(s, varname_len);					s += 4;
	memcpy(s, varname, varname_len);					s += varname_len;

	libssh2_htonu32(s, value_len);						s += 4;
	memcpy(s, value, value_len);						s += value_len;

	if (libssh2_packet_write(session, packet, packet_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send channel-request packet for setenv request", 0);
		LIBSSH2_FREE(session, packet);
		return -1;
	}
	LIBSSH2_FREE(session, packet);

	while (1) {
		unsigned char *data;
		unsigned long data_len;
		unsigned char local_channel[4];

		libssh2_htonu32(local_channel, channel->local.id);

		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_SUCCESS, &data, &data_len, 1, local_channel, 4, 1) == 0) {
			LIBSSH2_FREE(session, data);
			return 0;
		}

		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_FAILURE, &data, &data_len, 1, local_channel, 4, 0) == 0) {
			LIBSSH2_FREE(session, data);
			libssh2_error(session, LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED, "Unable to complete request for channel-setenv", 0);
			return -1;
		}
	}

	/* Never reached, just giving the compiler something to not complain about */
	return -1;
}
/* }}} */

/* {{{ libssh2_channel_request_pty_ex
 * Duh... Request a PTY
 */
LIBSSH2_API int libssh2_channel_request_pty_ex(LIBSSH2_CHANNEL *channel, char *term, int term_len,
																		 char *modes, int modes_len,
																		 int width, int height,
																		 int width_px, int height_px)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char *s, *packet;
	unsigned long packet_len = term_len + modes_len + 41; /*  packet_type(1) + channel(4) + pty_req_len(4) + "pty_req"(7) + want_reply(1) + 
															  term_len(4) + width(4) + height(4) + width_px(4) + height_px(4) + modes_len(4) */

	s = packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for pty-request", 0);
		return -1;
	}

	*(s++) = SSH_MSG_CHANNEL_REQUEST;
	libssh2_htonu32(s, channel->remote.id);						s += 4;
	libssh2_htonu32(s, sizeof("pty-req") - 1);					s += 4;
	memcpy(s, "pty-req", sizeof("pty-req") - 1);				s += sizeof("pty-req") - 1;

	*(s++) = 0xFF;

	libssh2_htonu32(s, term_len);								s += 4;
	if (term) {
		memcpy(s, term, term_len);								s += term_len;
	}

	libssh2_htonu32(s, width);									s += 4;
	libssh2_htonu32(s, height);									s += 4;
	libssh2_htonu32(s, width_px);								s += 4;
	libssh2_htonu32(s, height_px);								s += 4;

	libssh2_htonu32(s, modes_len);								s += 4;
	if (modes) {
		memcpy(s, modes, modes_len);							s += modes_len;
	}

	if (libssh2_packet_write(session, packet, packet_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send pty-request packet", 0);
		LIBSSH2_FREE(session, packet);
		return -1;
	}
	LIBSSH2_FREE(session, packet);

	while (1) {
		unsigned char *data;
		unsigned long data_len;
		unsigned char local_channel[4];

		libssh2_htonu32(local_channel, channel->local.id);

		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_SUCCESS, &data, &data_len, 1, local_channel, 4, 1) == 0) {
			LIBSSH2_FREE(session, data);
			return 0;
		}

		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_FAILURE, &data, &data_len, 1, local_channel, 4, 1) == 0) {
			LIBSSH2_FREE(session, data);
			libssh2_error(session, LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED, "Unable to complete request for channel request-pty", 0);
			return -1;
		}
	}

	/* Never reached, just giving the compiler something to not complain about */
	return -1;
}
/* }}} */

/* {{{ libssh2_channel_process_startup
 * Primitive for libssh2_channel_(shell|exec|subsystem)
 */
LIBSSH2_API int libssh2_channel_process_startup(LIBSSH2_CHANNEL *channel, char *request, int request_len, char *message, int message_len)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char *s, *packet;
	unsigned long packet_len = request_len + 10; /* packet_type(1) + channel(4) + request_len(4) + want_reply(1) */

	if (message) {
		packet_len += message_len + 4;
	}

	s = packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for channel-process request", 0);
		return -1;
	}

	*(s++) = SSH_MSG_CHANNEL_REQUEST;
	libssh2_htonu32(s, channel->remote.id);					s += 4;
	libssh2_htonu32(s, request_len);						s += 4;
	memcpy(s, request, request_len);						s += request_len;

	*(s++) = 0xFF;

	if (message) {
		libssh2_htonu32(s, message_len);					s += 4;
		memcpy(s, message, message_len);					s += message_len;
	}

	if (libssh2_packet_write(session, packet, packet_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send channel request", 0);
		LIBSSH2_FREE(session, packet);
		return -1;
	}
	LIBSSH2_FREE(session, packet);

	while (1) {
		unsigned char *data;
		unsigned long data_len;
		unsigned char local_channel[4];

		libssh2_htonu32(local_channel, channel->local.id);

		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_SUCCESS, &data, &data_len, 1, local_channel, 4, 1) == 0) {
			LIBSSH2_FREE(session, data);
			return 0;
		}

		if (libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_FAILURE, &data, &data_len, 1, local_channel, 4, 0) == 0) {
			LIBSSH2_FREE(session, data);
			libssh2_error(session, LIBSSH2_ERROR_CHANNEL_REQUEST_DENIED, "Unable to complete request for channel-process-startup", 0);
			return -1;
		}
	}

	/* Never reached, just giving the compiler something to not complain about */
	return -1;
}
/* }}} */

/* {{{ libssh2_channel_set_blocking
 * Set a channel's blocking mode on or off, similar to a socket's fcntl(fd, F_SETFL, O_NONBLOCK); type command
 */
LIBSSH2_API void libssh2_channel_set_blocking(LIBSSH2_CHANNEL *channel, int blocking)
{
	channel->blocking = blocking;
}
/* }}} */

/* {{{ libssh2_channel_flush_ex
 * Flush data from one (or all) stream
 * Returns number of bytes flushed, or -1 on failure
 */
LIBSSH2_API int libssh2_channel_flush_ex(LIBSSH2_CHANNEL *channel, int streamid)
{
	LIBSSH2_PACKET *packet = channel->session->packets.head;
	unsigned long refund_bytes = 0, flush_bytes = 0;

	while (packet) {
		LIBSSH2_PACKET *next = packet->next;
		unsigned char packet_type = packet->data[0];

		if (((packet_type == SSH_MSG_CHANNEL_DATA) || (packet_type == SSH_MSG_CHANNEL_EXTENDED_DATA)) &&
			(libssh2_ntohu32(packet->data + 1) == channel->local.id)) {
			/* It's our channel at least */
			if ((streamid == LIBSSH2_CHANNEL_FLUSH_ALL) ||
				((packet_type == SSH_MSG_CHANNEL_EXTENDED_DATA) && ((streamid == LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA) || (streamid = libssh2_ntohu32(packet->data + 5)))) ||
				((packet_type == SSH_MSG_CHANNEL_DATA) && (streamid == 0))) {

				/* It's one of the streams we wanted to flush */
				refund_bytes += packet->data_len - 13;
				flush_bytes += packet->data_len - packet->data_head;

				LIBSSH2_FREE(channel->session, packet->data);
				if (packet->prev) {
					packet->prev->next = packet->next;
				} else {
					channel->session->packets.head = packet->next;
				}
				if (packet->next) {
					packet->next->prev = packet->prev;
				} else {
					channel->session->packets.tail = packet->prev;
				}
				LIBSSH2_FREE(channel->session, packet);
			}
		}
		packet = next;
	}

	if (refund_bytes && channel->remote.window_size_initial) {
		unsigned char adjust[9]; /* packet_type(1) + channel(4) + adjustment(4) */

		/* Adjust the window based on the block we just freed */
		adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
		libssh2_htonu32(adjust + 1, channel->remote.id);
		libssh2_htonu32(adjust + 5, refund_bytes);

		if (libssh2_packet_write(channel->session, adjust, 9)) {
			libssh2_error(channel->session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send transfer-window adjustment packet", 0);
			return -1;
		} else {
			channel->remote.window_size += refund_bytes;
		}
	}

	return flush_bytes;
}
/* }}} */

/* {{{ libssh2_channel_handle_extended_data
 * How should extended data look to the calling app?
 * Keep it in separate channels[_read() _read_stdder()]? (NORMAL)
 * Merge the extended data to the standard data? [everything via _read()]? (MERGE)
 * Ignore it entirely [toss out packets as they come in]? (IGNORE)
 */
LIBSSH2_API void libssh2_channel_handle_extended_data(LIBSSH2_CHANNEL *channel, int ignore_mode)
{
	channel->remote.extended_data_ignore_mode = ignore_mode;

	if (ignore_mode == LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE) {
		libssh2_channel_flush_ex(channel, LIBSSH2_CHANNEL_FLUSH_EXTENDED_DATA);
	}
}
/* }}} */

/* {{{ libssh2_channel_read_ex
 * Read data from a channel
 */
LIBSSH2_API int libssh2_channel_read_ex(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, size_t buflen)
{
	LIBSSH2_SESSION *session = channel->session;
	int bytes_read = 0, blocking_read = 0;

	do {
		LIBSSH2_PACKET *packet = session->packets.head;

		/* Process any waiting packets */
		while (libssh2_packet_read(session, blocking_read) > 0) blocking_read = 0;

		while (packet && (bytes_read < buflen)) {
			/* In case packet gets destroyed during this iteration */
			LIBSSH2_PACKET *next = packet->next;

			/* Either we asked for a specific extended data stream (and data was available),
			 * or the standard stream (and data was available),
			 * or the standard stream with extended_data_merge enabled and data was available
			 */
			if ((stream_id  && (packet->data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA) && (channel->local.id == libssh2_ntohu32(packet->data + 1))) ||
				(!stream_id && (packet->data[0] == SSH_MSG_CHANNEL_DATA) && (channel->local.id == libssh2_ntohu32(packet->data + 1))) ||
				(!stream_id && (packet->data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA) && (channel->local.id == libssh2_ntohu32(packet->data + 1)) && (channel->remote.extended_data_ignore_mode == LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE))) {
				int want = buflen - bytes_read;
				int unlink_packet = 0;

				if (want >= (packet->data_len - packet->data_head)) {
					want = packet->data_len - packet->data_head;
					unlink_packet = 1;
				}

				memcpy(buf + bytes_read, packet->data + packet->data_head, want);
				packet->data_head += want;
				bytes_read += want;

				if (unlink_packet) {
					unsigned char adjust[9]; /* packet_type(1) + channel(4) + adjustment(4) */

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
					LIBSSH2_FREE(session, packet->data);

					if (channel->remote.window_size_initial) {
						/* Adjust the window based on the block we just freed */
						adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
						libssh2_htonu32(adjust + 1, channel->remote.id);
						libssh2_htonu32(adjust + 5, packet->data_len - (stream_id ? 13 : 9));

						if (libssh2_packet_write(session, adjust, 9)) {
							libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send transfer-window adjustment packet", 0);
						}

						LIBSSH2_FREE(session, packet);
					}
				}
			}
			packet = next;
		}
		blocking_read = 1;
	} while (channel->blocking && (bytes_read == 0) && !channel->remote.close);

	if (channel->blocking && (bytes_read == 0)) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_CLOSED, "Remote end has closed this channel", 0);
	}

	return bytes_read;
}
/* }}} */

/* {{{ libssh2_channel_write_ex
 * Send data to a channel
 */
LIBSSH2_API int libssh2_channel_write_ex(LIBSSH2_CHANNEL *channel, int stream_id, const char *buf, size_t buflen)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char *packet, *s;
	unsigned long packet_len;

	if (channel->local.close) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_CLOSED, "We've already closed this channel", 0);
		return -1;
	}

	if (channel->local.eof) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_EOF_SENT, "EOF has already been sight, data might be ignored", 0);
	}

	if (channel->blocking && channel->local.window_size_initial && (channel->local.window_size <= 0)) {
		/* twiddle our thumbs until there's window space available */
		if (libssh2_packet_read(session, 1) < 0) {
			/* Error occured, disconnect? */
			return -1;
		}
	}

	packet_len = buflen + (stream_id ? 13 : 9); /* packet_type(1) + channelno(4) [ + streamid(4) ] + buflen(4) */
	s = packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocte space for data transmission packet", 0);
		return -1;
	}

	*(s++) = stream_id ? SSH_MSG_CHANNEL_EXTENDED_DATA : SSH_MSG_CHANNEL_DATA;
	libssh2_htonu32(s, channel->remote.id);					s += 4;
	if (stream_id) {
		libssh2_htonu32(s, stream_id);						s += 4;
	}

	/* Don't exceed the remote end's limits */
	/* REMEMBER local means local as the SOURCE of the data */
	if (channel->local.window_size_initial && (buflen > channel->local.window_size)) {
		buflen = channel->local.window_size;
	}
	if (buflen > channel->local.packet_size) {
		buflen = channel->local.packet_size;
	}
	libssh2_htonu32(s, buflen);							s += 4;
	memcpy(s, buf, buflen);								s += buflen;

	if (libssh2_packet_write(session, packet, s - packet)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send channel data", 0);
		return -1;
	}
	/* Shrink local window size */
	channel->local.window_size -= buflen;

	LIBSSH2_FREE(session, packet);

	return buflen;
}
/* }}} */

/* {{{ libssh2_channel_send_eof
 * Send EOF on channel
 */
LIBSSH2_API int libssh2_channel_send_eof(LIBSSH2_CHANNEL *channel)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char packet[5]; /* packet_type(1) + channelno(4) */

	packet[0] = SSH_MSG_CHANNEL_EOF;
	libssh2_htonu32(packet + 1, channel->remote.id);
	if (libssh2_packet_write(session, packet, 5)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send EOF on channel", 0);
		return -1;
	}
	channel->local.eof = 1;

	return 0;
}
/* }}} */

/* {{{ libssh2_channel_eof
 * Read channel's eof status
 */
LIBSSH2_API int libssh2_channel_eof(LIBSSH2_CHANNEL *channel)
{
	LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_PACKET *packet = session->packets.head;

	while (packet) {
		if (((packet->data[0] == SSH_MSG_CHANNEL_DATA) || (packet->data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA)) && 
			(channel->local.id == libssh2_ntohu32(packet->data + 1))) {
			/* There's data waiting to be read yet, mask the EOF status */
			return 0;
		}
		packet = packet->next;
	}

	return channel->remote.eof;
}
/* }}} */

/* {{{ libssh2_channel_close
 * Close a channel
 */
LIBSSH2_API int libssh2_channel_close(LIBSSH2_CHANNEL *channel)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char packet[5];

	if (channel->local.close) {
		/* Already closed, act like we sent another close, even though we didn't... shhhhhh */
		return 0;
	}

	packet[0] = SSH_MSG_CHANNEL_CLOSE;
	libssh2_htonu32(packet + 1, channel->remote.id);
	if (libssh2_packet_write(session, packet, 5)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send close-channel request", 0);
		return -1;
	}
	channel->local.close = 1;

	/* TODO: Wait up to a timeout value for a CHANNEL_CLOSE to come back, to avoid the problem alluded to in channel_nextid */

	return 0;
}
/* }}} */

/* {{{ libssh2_channel_free
 * Make sure a channel is closed, then remove the channel from the session and free its resource(s)
 */
LIBSSH2_API int libssh2_channel_free(LIBSSH2_CHANNEL *channel)
{
	LIBSSH2_SESSION *session = channel->session;
	unsigned char channel_id[4], *data;
	unsigned long data_len;

	/* Allow channel freeing even when the socket has lost its connection */
	if (!channel->local.close && (session->socket_state == LIBSSH2_SOCKET_CONNECTED) &&
		libssh2_channel_close(channel)) {
		return -1;
	}

	/* channel->remote.close *might* not be set yet, Well... 
	 * We've sent the close packet, what more do you want?
	 * Just let packet_add ignore it when it finally arrives
	 */

	/* Clear out packets meant for this channel */
	libssh2_htonu32(channel_id, channel->local.id);
	while  ((libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_DATA, 		  &data, &data_len, 1, channel_id, 4, 1) >= 0) ||
			(libssh2_packet_ask_ex(session, SSH_MSG_CHANNEL_EXTENDED_DATA, &data, &data_len, 1, channel_id, 4, 1) >= 0)) {
		LIBSSH2_FREE(session, data);
	}

	/* free "channel_type" */
	if (channel->channel_type) {
		LIBSSH2_FREE(session, channel->channel_type);
	}

	/* Unlink from channel brigade */
	if (channel->prev) {
		channel->prev->next = channel->next;
	} else {
		session->channels.head = channel->next;
	}
	if (channel->next) {
		channel->next->prev = channel->prev;
	} else {
		session->channels.tail = channel->prev;
	}

	LIBSSH2_FREE(session, channel);

	return 0;
}
/* }}} */
