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
#include <stdlib.h>

#define LIBSSH2_SCP_RESPONSE_BUFLEN		256

/* {{{ libssh2_scp_recv
 * Open a channel and request a remote file via SCP
 */
LIBSSH2_API LIBSSH2_CHANNEL *libssh2_scp_recv(LIBSSH2_SESSION *session, const char *path, struct stat *sb)
{
	int path_len = strlen(path);
	unsigned char *command, response[LIBSSH2_SCP_RESPONSE_BUFLEN];
	unsigned long command_len = path_len + sizeof("scp -f "), response_len;
	LIBSSH2_CHANNEL *channel;
	long mode = 0, size = 0, mtime = 0, atime = 0;

	if (sb) {
		command_len++;
	}

	command = LIBSSH2_ALLOC(session, command_len);
	if (!command) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a command buffer for scp session", 0);
		return NULL;
	}
	if (sb) {
		memcpy(command, "scp -pf ", sizeof("scp -pf ") - 1);
		memcpy(command + sizeof("scp -pf ") - 1, path, path_len);
	} else {
		memcpy(command, "scp -f ", sizeof("scp -f ") - 1);
		memcpy(command + sizeof("scp -f ") - 1, path, path_len);
	}
	command[command_len - 1] = '\0';

#ifdef LIBSSH2_DEBUG_SCP
	_libssh2_debug(session, LIBSSH2_DBG_SCP, "Opening channel for SCP receive");
#endif
	/* Allocate a channel */
	if ((channel = libssh2_channel_open_session(session)) == NULL) {
		LIBSSH2_FREE(session, command);
		return NULL;
	}
	/* Use blocking I/O for negotiation phase */
	libssh2_channel_set_blocking(channel, 1);

	/* Request SCP for the desired file */
	if (libssh2_channel_process_startup(channel, "exec", sizeof("exec") - 1, command, command_len)) {
		LIBSSH2_FREE(session, command);
		libssh2_channel_free(channel);
		return NULL;
	}
	LIBSSH2_FREE(session, command);

#ifdef LIBSSH2_DEBUG_SCP
	_libssh2_debug(session, LIBSSH2_DBG_SCP, "Sending initial wakeup");
#endif
	/* SCP ACK */
	response[0] = '\0';
	if (libssh2_channel_write(channel, response, 1) != 1) {
		libssh2_channel_free(channel);
		return NULL;
	}

	/* Parse SCP response */
	response_len = 0;
	while (sb && (response_len < LIBSSH2_SCP_RESPONSE_BUFLEN)) {
		unsigned char *s, *p;

		if (libssh2_channel_read(channel, response + response_len, 1) <= 0) {
			/* Timeout, give up */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Timed out waiting for SCP response", 0);
			libssh2_channel_free(channel);
			return NULL;
		}
		response_len++;

		if (response[0] != 'T') {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid data in SCP response, missing Time data", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		if ((response_len > 1) && 
			((response[response_len-1] < '0') || (response[response_len-1] > '9')) && 
			(response[response_len-1] != ' ') && 
			(response[response_len-1] != '\r') &&
			(response[response_len-1] != '\n')) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid data in SCP response", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		if ((response_len < 9) || (response[response_len-1] != '\n')) {
			if (response_len == LIBSSH2_SCP_RESPONSE_BUFLEN) {
				/* You had your chance */
				libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Unterminated response from SCP server", 0);
				libssh2_channel_free(channel);
				return NULL;
			}
			/* Way too short to be an SCP response,  or not done yet, short circuit */
			continue;
		}

		/* We're guaranteed not to go under response_len == 0 by the logic above */
		while ((response[response_len-1] == '\r') || (response[response_len-1] == '\n')) response_len--;
		response[response_len] = '\0';

		if (response_len < 8) {
			/* EOL came too soon */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, too short", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		s = response + 1;

		p = strchr(s, ' ');
		if (!p || ((p - s) <= 0)) {
			/* No spaces or space in the wrong spot */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, malformed mtime", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		*(p++) = '\0';
		/* Make sure we don't get fooled by leftover values */
		errno = 0;
		mtime = strtol(s, NULL, 10);
		if (errno) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, invalid mtime", 0);
			libssh2_channel_free(channel);
			return NULL;
		}
		s = strchr(p, ' ');
		if (!s || ((s - p) <= 0)) {
			/* No spaces or space in the wrong spot */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, malformed mtime.usec", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		/* Ignore mtime.usec */
		s++;
		p = strchr(s, ' ');
		if (!p || ((p - s) <= 0)) {
			/* No spaces or space in the wrong spot */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, too short or malformed", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		*(p++) = '\0';
		/* Make sure we don't get fooled by leftover values */
		errno = 0;
		atime = strtol(s, NULL, 10);
		if (errno) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, invalid atime", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		/* SCP ACK */
		response[0] = '\0';
		if (libssh2_channel_write(channel, response, 1) != 1) {
			libssh2_channel_free(channel);
			return NULL;
		}
#ifdef LIBSSH2_DEBUG_SCP
		_libssh2_debug(session, LIBSSH2_DBG_SCP, "mtime = %ld, atime = %ld", mtime, atime);
#endif

		/* We *should* check that atime.usec is valid, but why let that stop use? */
		break;
	}

	response_len = 0;
	while (response_len < LIBSSH2_SCP_RESPONSE_BUFLEN) {
		char *s, *p, *e = NULL;

		if (libssh2_channel_read(channel, response + response_len, 1) <= 0) {
			/* Timeout, give up */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Timed out waiting for SCP response", 0);
			libssh2_channel_free(channel);
			return NULL;
		}
		response_len++;

		if (response[0] != 'C') {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		if ((response_len > 1) && 
			(response[response_len-1] != '\r') &&
			(response[response_len-1] != '\n') &&
			((response[response_len-1] < 32) || (response[response_len-1] > 126))) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid data in SCP response", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		if ((response_len < 7) || (response[response_len-1] != '\n')) {
			if (response_len == LIBSSH2_SCP_RESPONSE_BUFLEN) {
				/* You had your chance */
				libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Unterminated response from SCP server", 0);
				libssh2_channel_free(channel);
				return NULL;
			}
			/* Way too short to be an SCP response,  or not done yet, short circuit */
			continue;
		}

		/* We're guaranteed not to go under response_len == 0 by the logic above */
		while ((response[response_len-1] == '\r') || (response[response_len-1] == '\n')) response_len--;
		response[response_len] = '\0';

		if (response_len < 6) {
			/* EOL came too soon */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, too short", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		s = response + 1;
		
		p = strchr(s, ' ');
		if (!p || ((p - s) <= 0)) {
			/* No spaces or space in the wrong spot */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, malformed mode", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		*(p++) = '\0';
		/* Make sure we don't get fooled by leftover values */
		errno = 0;
		mode = strtol(s, &e, 8);
		if ((e && *e) || errno) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, invalid mode", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		s = strchr(p, ' ');
		if (!s || ((s - p) <= 0)) {
			/* No spaces or space in the wrong spot */
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, too short or malformed", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		*(s++) = '\0';
		/* Make sure we don't get fooled by leftover values */
		errno = 0;
		size = strtol(p, &e, 10);
		if ((e && *e) || errno) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid response from SCP server, invalid size", 0);
			libssh2_channel_free(channel);
			return NULL;
		}

		/* SCP ACK */
		response[0] = '\0';
		if (libssh2_channel_write(channel, response, 1) != 1) {
			libssh2_channel_free(channel);
			return NULL;
		}
#ifdef LIBSSH2_DEBUG_SCP
	_libssh2_debug(session, LIBSSH2_DBG_SCP, "mod = 0%lo size = %ld", mode, size);
#endif

		/* We *should* check that basename is valid, but why let that stop us? */
		break;
	}

	if (sb) {
		memset(sb, 0, sizeof(struct stat));

		sb->st_mtime = mtime;
		sb->st_atime = atime;
		sb->st_size = size;
		sb->st_mode = mode;
	}
	/* Revert to non-blocking and let the data BEGIN! */
	libssh2_channel_set_blocking(channel, 0);

	return channel;
}
/* }}} */

/* {{{ libssh2_scp_send_ex
 * Send a file using SCP
 */
LIBSSH2_API LIBSSH2_CHANNEL *libssh2_scp_send_ex(LIBSSH2_SESSION *session, const char *path, int mode, size_t size, long mtime, long atime)
{
	int path_len = strlen(path);
	unsigned char *command, response[LIBSSH2_SCP_RESPONSE_BUFLEN];
	unsigned long response_len, command_len = path_len + sizeof("scp -t ");
	unsigned const char *base;
	LIBSSH2_CHANNEL *channel;

	if (mtime || atime) {
		command_len++;
	}

	command = LIBSSH2_ALLOC(session, command_len);
	if (!command) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a command buffer for scp session", 0);
		return NULL;
	}

	if (mtime || atime) {
		memcpy(command, "scp -pt ", sizeof("scp -pt ") - 1);
		memcpy(command + sizeof("scp -pt ") - 1, path, path_len);
	} else {
		memcpy(command, "scp -t ", sizeof("scp -t ") - 1);
		memcpy(command + sizeof("scp -t ") - 1, path, path_len);
	}
	command[command_len - 1] = '\0';

#ifdef LIBSSH2_DEBUG_SCP
	_libssh2_debug(session, LIBSSH2_DBG_SCP, "Opening channel for SCP send");
#endif
	/* Allocate a channel */
	if ((channel = libssh2_channel_open_session(session)) == NULL) {
	        /* previous call set libssh2_session_last_error(), pass it through */
		LIBSSH2_FREE(session, command);
		return NULL;
	}
	/* Use blocking I/O for negotiation phase */
	libssh2_channel_set_blocking(channel, 1);

	/* Request SCP for the desired file */
	if (libssh2_channel_process_startup(channel, "exec", sizeof("exec") - 1, command, command_len)) {
	        /* previous call set libssh2_session_last_error(), pass it through */
		LIBSSH2_FREE(session, command);
		libssh2_channel_free(channel);
		return NULL;
	}
	LIBSSH2_FREE(session, command);

	/* Wait for ACK */
	if ((libssh2_channel_read(channel, response, 1) <= 0) || (response[0] != 0)) {
		libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid ACK response from remote", 0);
		libssh2_channel_free(channel);
		return NULL;
	}

	/* Send mtime and atime to be used for file */
	if (mtime || atime) {
		response_len = snprintf(response, LIBSSH2_SCP_RESPONSE_BUFLEN, "T%ld 0 %ld 0\n", mtime, atime);
#ifdef LIBSSH2_DEBUG_SCP
		_libssh2_debug(session, LIBSSH2_DBG_SCP, "Sent %s", response);
#endif
		if (libssh2_channel_write(channel, response, response_len) != response_len) {
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send time data for SCP file", 0);
			libssh2_channel_free(channel);
			return NULL;
		}
		/* Wait for ACK */
		if ((libssh2_channel_read(channel, response, 1) <= 0) || (response[0] != 0)) {
			libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid ACK response from remote", 0);
			libssh2_channel_free(channel);
			return NULL;
		}
	}

	/* Send mode, size, and basename */
	base = strrchr(path, '/');
	if (base) {
		base++;
	} else {
		base = path;
	}

	response_len = snprintf(response, LIBSSH2_SCP_RESPONSE_BUFLEN, "C0%o %lu %s\n", mode, (unsigned long)size, base);
#ifdef LIBSSH2_DEBUG_SCP
	_libssh2_debug(session, LIBSSH2_DBG_SCP, "Sent %s", response);
#endif
	if (libssh2_channel_write(channel, response, response_len) != response_len) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send core file data for SCP file", 0);
		libssh2_channel_free(channel);
		return NULL;
	}
	/* Wait for ACK */
	if ((libssh2_channel_read(channel, response, 1) <= 0) || (response[0] != 0)) {
		libssh2_error(session, LIBSSH2_ERROR_SCP_PROTOCOL, "Invalid ACK response from remote", 0);
		libssh2_channel_free(channel);
		return NULL;
	}

	/* Ready to start, switch to non-blocking and let calling app send file */
	libssh2_channel_set_blocking(channel, 0);

	return channel;
}
/* }}} */

