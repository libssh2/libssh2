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
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>

#ifdef HAVE_GETTIMEOFDAY
#include <sys/time.h>
#include <math.h>
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



/* {{{ libssh2_default_alloc
 */
static LIBSSH2_ALLOC_FUNC(libssh2_default_alloc)
{
	return malloc(count);
}
/* }}} */

/* {{{ libssh2_default_free
 */
static LIBSSH2_FREE_FUNC(libssh2_default_free)
{
	free(ptr);
}
/* }}} */

/* {{{ libssh2_default_realloc
 */
static LIBSSH2_REALLOC_FUNC(libssh2_default_realloc)
{
	return realloc(ptr, count);
}
/* }}} */

/* {{{ libssh2_banner_receive
 * Wait for a hello from the remote host
 * Allocate a buffer and store the banner in session->remote.banner
 * Returns: 0 on success, 1 on failure
 */
static int libssh2_banner_receive(LIBSSH2_SESSION *session)
{
	char banner[256];
	int banner_len = 0;

	while ((banner_len < sizeof(banner)) &&
			((banner_len == 0) || (banner[banner_len-1] != '\n'))) {
		char c = '\0';
		int ret;

		ret = recv(session->socket_fd, &c, 1, LIBSSH2_SOCKET_RECV_FLAGS(session));

		if (ret < 0) {
#ifdef WIN32
			switch (WSAGetLastError()) {
				case WSAEWOULDBLOCK:
					errno = EAGAIN;
					break;
				case WSAENOTSOCK:
					errno = EBADF;
					break;
				case WSAENOTCONN:
				case WSAECONNABORTED:
					errno = ENOTCONN;
					break;
				case WSAEINTR:
					errno = EINTR;
					break;
			}
#endif /* WIN32 */
			if (errno != EAGAIN) {
				/* Some kinda error, but don't break for non-blocking issues */
				return 1;
			}
		}

		if (ret <= 0) continue;

		if (c == '\0') {
			/* NULLs are not allowed in SSH banners */
			return 1;
		}

		banner[banner_len++] = c;
	}

	while (banner_len &&
			((banner[banner_len-1] == '\n') || (banner[banner_len-1] == '\r'))) {
		banner_len--;
	}

	if (!banner_len) return 1;

	session->remote.banner = LIBSSH2_ALLOC(session, banner_len + 1);
	memcpy(session->remote.banner, banner, banner_len);
	session->remote.banner[banner_len] = '\0';
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Received Banner: %s", session->remote.banner);
#endif
	return 0;
}
/* }}} */

/* {{{ libssh2_banner_send
 * Send the default banner, or the one set via libssh2_setopt_string
 */
static int libssh2_banner_send(LIBSSH2_SESSION *session)
{
	char *banner = LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF;
	int banner_len = sizeof(LIBSSH2_SSH_DEFAULT_BANNER_WITH_CRLF) - 1;

	if (session->local.banner) {
		/* setopt_string will have given us our \r\n characters */
		banner_len = strlen(session->local.banner);
		banner = session->local.banner;
	}
#ifdef LIBSSH2_DEBUG_TRANSPORT
{
	/* Hack and slash to avoid sending CRLF in debug output */
	char banner_dup[256];

	if (banner_len < 256) {
		memcpy(banner_dup, banner, banner_len - 2);
		banner_dup[banner_len - 2] = '\0';
	} else {
		memcpy(banner_dup, banner, 255);
		banner[255] = '\0';
	}

	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Sending Banner: %s", banner_dup);
}
#endif

	return (send(session->socket_fd, banner, banner_len, LIBSSH2_SOCKET_SEND_FLAGS(session)) == banner_len) ? 0 : 1;
}
/* }}} */

/* {{{ libssh2_banner_set
 * Set the local banner
 */
LIBSSH2_API int libssh2_banner_set(LIBSSH2_SESSION *session, const char *banner)
{
	int banner_len = banner ? strlen(banner) : 0;

	if (session->local.banner) {
		LIBSSH2_FREE(session, session->local.banner);
		session->local.banner = NULL;
	}

	if (!banner_len) {
		return 0;
	}

	session->local.banner = LIBSSH2_ALLOC(session, banner_len + 3);
	if (!session->local.banner) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for local banner", 0);
		return -1;
	}

	memcpy(session->local.banner, banner, banner_len);
#ifdef LIBSSH2_DEBUG_TRANSPORT
	session->local.banner[banner_len] = '\0';
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Setting local Banner: %s", session->local.banner);
#endif
	session->local.banner[banner_len++] = '\r';
	session->local.banner[banner_len++] = '\n';
	session->local.banner[banner_len++] = '\0';

	return 0;
}
/* }}} */

/* {{{ proto libssh2_session_init
 * Allocate and initialize a libssh2 session structure
 * Allows for malloc callbacks in case the calling program has its own memory manager
 * It's allowable (but unadvisable) to define some but not all of the malloc callbacks
 * An additional pointer value may be optionally passed to be sent to the callbacks (so they know who's asking)
 */
LIBSSH2_API LIBSSH2_SESSION *libssh2_session_init_ex(
			LIBSSH2_ALLOC_FUNC((*my_alloc)),
			LIBSSH2_FREE_FUNC((*my_free)),
			LIBSSH2_REALLOC_FUNC((*my_realloc)),
			void *abstract)
{
	LIBSSH2_ALLOC_FUNC((*local_alloc))		= libssh2_default_alloc;
	LIBSSH2_FREE_FUNC((*local_free))		= libssh2_default_free;
	LIBSSH2_REALLOC_FUNC((*local_realloc))	= libssh2_default_realloc;
	LIBSSH2_SESSION *session;

	if (my_alloc)	local_alloc		= my_alloc;
	if (my_free)	local_free		= my_free;
	if (my_realloc)	local_realloc	= my_realloc;

	session = local_alloc(sizeof(LIBSSH2_SESSION), abstract);
	memset(session, 0, sizeof(LIBSSH2_SESSION));
	session->alloc		= local_alloc;
	session->free		= local_free;
	session->realloc	= local_realloc;
	session->abstract	= abstract;
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "New session resource allocated");
#endif

	return session;
}
/* }}} */

/* {{{ libssh2_session_callback_set
 * Set (or reset) a callback function
 * Returns the prior address
 */
LIBSSH2_API void* libssh2_session_callback_set(LIBSSH2_SESSION *session, int cbtype, void *callback)
{
	void *oldcb;

	switch (cbtype) {
		case LIBSSH2_CALLBACK_IGNORE:
			oldcb = session->ssh_msg_ignore;
			session->ssh_msg_ignore = callback;
			return oldcb;
			break;
		case LIBSSH2_CALLBACK_DEBUG:
			oldcb = session->ssh_msg_debug;
			session->ssh_msg_debug = callback;
			return oldcb;
			break;
		case LIBSSH2_CALLBACK_DISCONNECT:
			oldcb = session->ssh_msg_disconnect;
			session->ssh_msg_disconnect = callback;
			return oldcb;
			break;
		case LIBSSH2_CALLBACK_MACERROR:
			oldcb = session->macerror;
			session->macerror = callback;
			return oldcb;
			break;
		case LIBSSH2_CALLBACK_X11:
			oldcb = session->x11;
			session->x11 = callback;
			return oldcb;
			break;
	}
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Setting Callback %d", cbtype);
#endif

	return NULL;
}
/* }}} */

/* {{{ proto libssh2_session_startup
 * session: LIBSSH2_SESSION struct allocated and owned by the calling program
 * Returns: 0 on success, or non-zero on failure
 * Any memory allocated by libssh2 will use alloc/realloc/free callbacks in session
 * socket *must* be populated with an opened socket
 */
LIBSSH2_API int libssh2_session_startup(LIBSSH2_SESSION *session, int socket)
{
	unsigned char *data;
	unsigned long data_len;
	unsigned char service[sizeof("ssh-userauth") + 5 - 1];
	unsigned long service_length;

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "session_startup for socket %d", socket);
#endif
	if (socket < 0) {
		/* Did we forget something? */
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_NONE, "Bad socket provided", 0);
		return LIBSSH2_ERROR_SOCKET_NONE;
	}
	session->socket_fd = socket;

	/* TODO: Liveness check */
	if (libssh2_banner_send(session)) {
		/* Unable to send banner? */
		libssh2_error(session, LIBSSH2_ERROR_BANNER_SEND, "Error sending banner to remote host", 0);
		return LIBSSH2_ERROR_BANNER_SEND;
	}

	if (libssh2_banner_receive(session)) {
		/* Unable to receive banner from remote */
		libssh2_error(session, LIBSSH2_ERROR_BANNER_NONE, "Timeout waiting for banner", 0);
		return LIBSSH2_ERROR_BANNER_NONE;
	}

	if (libssh2_kex_exchange(session, 0)) {
		libssh2_error(session, LIBSSH2_ERROR_KEX_FAILURE, "Unable to exchange encryption keys", 0);
		return LIBSSH2_ERROR_KEX_FAILURE;
	}

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Requesting userauth service");
#endif
	/* Request the userauth service */
	service[0] = SSH_MSG_SERVICE_REQUEST;
	libssh2_htonu32(service + 1, sizeof("ssh-userauth") - 1);
	memcpy(service + 5, "ssh-userauth", sizeof("ssh-userauth") - 1);
	if (libssh2_packet_write(session, service, sizeof("ssh-userauth") + 5 - 1)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to ask for ssh-userauth service", 0);
		return LIBSSH2_ERROR_SOCKET_SEND;
	}

	if (libssh2_packet_require(session, SSH_MSG_SERVICE_ACCEPT, &data, &data_len)) {
		return LIBSSH2_ERROR_SOCKET_DISCONNECT;
	}
	service_length = libssh2_ntohu32(data + 1);

	if ((service_length != (sizeof("ssh-userauth") - 1)) ||
		strncmp("ssh-userauth", data + 5, service_length)) {
		LIBSSH2_FREE(session, data);
		libssh2_error(session, LIBSSH2_ERROR_PROTO, "Invalid response received from server", 0);
		return LIBSSH2_ERROR_PROTO;
	}
	LIBSSH2_FREE(session, data);

	return 0;
}
/* }}} */

/* {{{ proto libssh2_session_free
 * Frees the memory allocated to the session
 * Also closes and frees any channels attached to this session
 */
LIBSSH2_API void libssh2_session_free(LIBSSH2_SESSION *session)
{
#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Freeing session resource", session->remote.banner);
#endif
	while (session->channels.head) {
		LIBSSH2_CHANNEL *tmp = session->channels.head;

		libssh2_channel_free(session->channels.head);
		if (tmp == session->channels.head) {
			/* channel_free couldn't do it's job, perform a messy cleanup */
			tmp = session->channels.head;

			/* unlink */
			session->channels.head = tmp->next;

			/* free */
			LIBSSH2_FREE(session, tmp);

			/* reverse linking isn't important here, we're killing the structure */
		}
	}

	while (session->listeners) {
		libssh2_channel_forward_cancel(session->listeners);
	}

	if (session->state & LIBSSH2_STATE_NEWKEYS) {
		/* hostkey */
		if (session->hostkey && session->hostkey->dtor) {
			session->hostkey->dtor(session, &session->server_hostkey_abstract);
		}

		/* Client to Server */
		/* crypt */
		if (session->local.crypt) {
			if (session->local.crypt->flags & LIBSSH2_CRYPT_METHOD_FLAG_EVP) {
				if (session->local.crypt_abstract) {
					EVP_CIPHER_CTX_cleanup(session->local.crypt_abstract);
					LIBSSH2_FREE(session, session->local.crypt_abstract);
					session->local.crypt_abstract = NULL;
				}
			} else if (session->local.crypt->dtor) {
				session->local.crypt->dtor(session, &session->local.crypt_abstract);
			}
		}
		/* comp */
		if (session->local.comp && session->local.comp->dtor) {
			session->local.comp->dtor(session, 1, &session->local.comp_abstract);
		}
		/* mac */
		if (session->local.mac && session->local.mac->dtor) {
			session->local.mac->dtor(session, &session->local.mac_abstract);
		}

		/* Server to Client */
		/* crypt */
		if (session->remote.crypt) {
			if (session->remote.crypt->flags & LIBSSH2_CRYPT_METHOD_FLAG_EVP) {
				if (session->remote.crypt_abstract) {
					EVP_CIPHER_CTX_cleanup(session->remote.crypt_abstract);
					LIBSSH2_FREE(session, session->remote.crypt_abstract);
					session->remote.crypt_abstract = NULL;
				}
			} else if (session->remote.crypt->dtor) {
				session->remote.crypt->dtor(session, &session->remote.crypt_abstract);
			}
		}
		/* comp */
		if (session->remote.comp && session->remote.comp->dtor) {
			session->remote.comp->dtor(session, 0, &session->remote.comp_abstract);
		}
		/* mac */
		if (session->remote.mac && session->remote.mac->dtor) {
			session->remote.mac->dtor(session, &session->remote.mac_abstract);
		}

		/* session_id */
		if (session->session_id) {
			LIBSSH2_FREE(session, session->session_id);
		}
	}

	/* Free banner(s) */
	if (session->remote.banner) {
		LIBSSH2_FREE(session, session->remote.banner);
	}
	if (session->local.banner) {
		LIBSSH2_FREE(session, session->local.banner);
	}

	/* Free preference(s) */
	if (session->kex_prefs) {
		LIBSSH2_FREE(session, session->kex_prefs);
	}
	if (session->hostkey_prefs) {
		LIBSSH2_FREE(session, session->hostkey_prefs);
	}

	if (session->local.crypt_prefs) {
		LIBSSH2_FREE(session, session->local.crypt_prefs);
	}
	if (session->local.mac_prefs) {
		LIBSSH2_FREE(session, session->local.mac_prefs);
	}
	if (session->local.comp_prefs) {
		LIBSSH2_FREE(session, session->local.comp_prefs);
	}
	if (session->local.lang_prefs) {
		LIBSSH2_FREE(session, session->local.lang_prefs);
	}

	if (session->remote.crypt_prefs) {
		LIBSSH2_FREE(session, session->remote.crypt_prefs);
	}
	if (session->remote.mac_prefs) {
		LIBSSH2_FREE(session, session->remote.mac_prefs);
	}
	if (session->remote.comp_prefs) {
		LIBSSH2_FREE(session, session->remote.comp_prefs);
	}
	if (session->remote.lang_prefs) {
		LIBSSH2_FREE(session, session->remote.lang_prefs);
	}

	/* Cleanup any remaining packets */
	while (session->packets.head) {
		LIBSSH2_PACKET *tmp = session->packets.head;

		/* unlink */
		session->packets.head = tmp->next;

		/* free */
		LIBSSH2_FREE(session, tmp->data);
		LIBSSH2_FREE(session, tmp);
	}

	LIBSSH2_FREE(session, session);
}
/* }}} */

/* {{{ libssh2_session_disconnect_ex
 */
LIBSSH2_API int libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason, const char *description, const char *lang)
{
	unsigned char *s, *data;
	unsigned long data_len, descr_len = 0, lang_len = 0;

#ifdef LIBSSH2_DEBUG_TRANSPORT
	_libssh2_debug(session, LIBSSH2_DBG_TRANS, "Disconnecting: reason=%d, desc=%s, lang=%s", reason, description, lang);
#endif
	if (description) {
		descr_len = strlen(description);
	}
	if (lang) {
		lang_len = strlen(lang);
	}
	data_len = descr_len + lang_len + 13; /* packet_type(1) + reason code(4) + descr_len(4) + lang_len(4) */

	s = data = LIBSSH2_ALLOC(session, data_len);
	if (!data) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for disconnect packet", 0);
		return -1;
	}

	*(s++) = SSH_MSG_DISCONNECT;
	libssh2_htonu32(s, reason);				s += 4;

	libssh2_htonu32(s, descr_len);			s += 4;
	if (description) {
		memcpy(s, description, descr_len);
		s += descr_len;
	}

	libssh2_htonu32(s, lang_len);			s += 4;
	if (lang) {
		memcpy(s, lang, lang_len);
		s += lang_len;
	}

	libssh2_packet_write(session, data, data_len);

	LIBSSH2_FREE(session, data);

	return 0;
}
/* }}} */

/* {{{ libssh2_session_methods
 * Return the currently active methods for method_type
 * NOTE: Currently lang_cs and lang_sc are ALWAYS set to empty string regardless of actual negotiation
 * Strings should NOT be freed
 */
LIBSSH2_API const char *libssh2_session_methods(LIBSSH2_SESSION *session, int method_type)
{
	/* All methods have char *name as their first element */
	LIBSSH2_KEX_METHOD *method = NULL;

	switch(method_type) {
		case LIBSSH2_METHOD_KEX:
			method = session->kex;
		break;
		case LIBSSH2_METHOD_HOSTKEY:
			method = (LIBSSH2_KEX_METHOD*)session->hostkey;
		break;
		case LIBSSH2_METHOD_CRYPT_CS:
			method = (LIBSSH2_KEX_METHOD*)session->local.crypt;
		break;
		case LIBSSH2_METHOD_CRYPT_SC:
			method = (LIBSSH2_KEX_METHOD*)session->remote.crypt;
		break;
		case LIBSSH2_METHOD_MAC_CS:
			method = (LIBSSH2_KEX_METHOD*)session->local.mac;
		break;
		case LIBSSH2_METHOD_MAC_SC:
			method = (LIBSSH2_KEX_METHOD*)session->remote.mac;
		break;
		case LIBSSH2_METHOD_COMP_CS:
			method = (LIBSSH2_KEX_METHOD*)session->local.comp;
		break;
		case LIBSSH2_METHOD_COMP_SC:
			method = (LIBSSH2_KEX_METHOD*)session->remote.comp;
		break;
		case LIBSSH2_METHOD_LANG_CS:
			return "";
		break;
		case LIBSSH2_METHOD_LANG_SC:
			return "";
		break;
		default:
			libssh2_error(session, LIBSSH2_ERROR_INVAL, "Invalid parameter specified for method_type", 0);
			return NULL;
		break;
	}

	if (!method) {
		libssh2_error(session, LIBSSH2_ERROR_METHOD_NONE, "No method negotiated", 0);
		return NULL;
	}

	return method->name;
}
/* }}} */

/* {{{ libssh2_session_abstract
 * Retrieve a pointer to the abstract property
 */
LIBSSH2_API void **libssh2_session_abstract(LIBSSH2_SESSION *session)
{
	return &session->abstract;
}
/* }}} */

/* {{{ libssh2_session_last_error
 * Returns error code and populates an error string into errmsg
 * If want_buf is non-zero then the string placed into errmsg must be freed by the calling program
 * Otherwise it is assumed to be owned by libssh2
 */
LIBSSH2_API int libssh2_session_last_error(LIBSSH2_SESSION *session, char **errmsg, int *errmsg_len, int want_buf)
{
	/* No error to report */
	if (!session->err_code) {
		if (errmsg) {
			if (want_buf) {
				*errmsg = LIBSSH2_ALLOC(session, 1);
				if (*errmsg) {
					**errmsg = 0;
				}
			} else {
				*errmsg = "";
			}
		}
		if (errmsg_len) {
			*errmsg_len = 0;
		}
		return 0;
	}

	if (errmsg) {
		char *serrmsg = session->err_msg ? session->err_msg : "";
		int ownbuf = session->err_msg ? session->err_should_free : 0;

		if (want_buf) {
			if (ownbuf) {
				/* Just give the calling program the buffer */
				*errmsg = serrmsg;
				session->err_should_free = 0;
			} else {
				/* Make a copy so the calling program can own it */
				*errmsg = LIBSSH2_ALLOC(session, session->err_msglen + 1);
				if (*errmsg) {
					memcpy(*errmsg, session->err_msg, session->err_msglen);
					(*errmsg)[session->err_msglen] = 0;
				}
			}
		} else {
			*errmsg = serrmsg;
		}
	}

	if (errmsg_len) {
		*errmsg_len = session->err_msglen;
	}

	return session->err_code;
}
/* }}} */

/* {{{ libssh2_session_flag
 * Set/Get session flags
 * Passing flag==0 will avoid changing session->flags while still returning its current value
 */
LIBSSH2_API int libssh2_session_flag(LIBSSH2_SESSION *session, int flag, int value)
{
	if (value) {
		session->flags |= flag;
	} else {
		session->flags &= ~flag;
	}

	return session->flags;
}
/* }}} */

/* {{{ libssh2_poll_channel_read
 * Returns 0 if no data is waiting on channel,
 * non-0 if data is available
 */
LIBSSH2_API int libssh2_poll_channel_read(LIBSSH2_CHANNEL *channel, int extended)
{
	LIBSSH2_SESSION *session = channel->session;
	LIBSSH2_PACKET *packet = session->packets.head;

	while (packet) {
		if (((packet->data[0] == SSH_MSG_CHANNEL_DATA) && (extended == 0) && (channel->local.id == libssh2_ntohu32(packet->data + 1))) ||
			((packet->data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA) && (extended != 0) && (channel->local.id == libssh2_ntohu32(packet->data + 1)))) {
			/* Found data waiting to be read */
			return 1;
		}
		packet = packet->next;
	}

	return 0;
}
/* }}} */

/* {{{ libssh2_poll_channel_write
 * Returns 0 if writing to channel would block,
 * non-0 if data can be written without blocking
 */
inline int libssh2_poll_channel_write(LIBSSH2_CHANNEL *channel)
{
	return channel->local.window_size ? 1 : 0;
}
/* }}} */

/* {{{ libssh2_poll_listener_queued
 * Returns 0 if no connections are waiting to be accepted
 * non-0 if one or more connections are available
 */
inline int libssh2_poll_listener_queued(LIBSSH2_LISTENER *listener)
{
	return listener->queue ? 1 : 0;
}
/* }}} */

/* {{{ libssh2_poll
 * Poll sockets, channels, and listeners for activity
 */
LIBSSH2_API int libssh2_poll(LIBSSH2_POLLFD *fds, unsigned int nfds, long timeout)
{
	long timeout_remaining;
	int i, active_fds;
#ifdef HAVE_POLL
	LIBSSH2_SESSION *session = NULL;
	struct pollfd sockets[nfds];

	/* Setup sockets for polling */
	for(i = 0; i < nfds; i++) {
		fds[i].revents = 0;
		switch (fds[i].type) {
			case LIBSSH2_POLLFD_SOCKET:
				sockets[i].fd = fds[i].fd.socket;
				sockets[i].events  = fds[i].events;
				sockets[i].revents = 0;
				break;
			case LIBSSH2_POLLFD_CHANNEL:
				sockets[i].fd = fds[i].fd.channel->session->socket_fd;
				sockets[i].events  = POLLIN;
				sockets[i].revents = 0;
				if (!session) session = fds[i].fd.channel->session;
				break;
			case LIBSSH2_POLLFD_LISTENER:
				sockets[i].fd = fds[i].fd.listener->session->socket_fd;
				sockets[i].events  = POLLIN;
				sockets[i].revents = 0;
				if (!session) session = fds[i].fd.listener->session;
				break;
			default:
				if (session) libssh2_error(session, LIBSSH2_ERROR_INVALID_POLL_TYPE, "Invalid descriptor passed to libssh2_poll()", 0);
				return -1;
		}
	}
#elif defined(HAVE_SELECT)
	LIBSSH2_SESSION *session = NULL;
	int maxfd = 0;
	fd_set rfds,wfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	for(i = 0; i < nfds; i++) {
		fds[i].revents = 0;
		switch (fds[i].type) {
			case LIBSSH2_POLLFD_SOCKET:
				if (fds[i].events & LIBSSH2_POLLFD_POLLIN) {
					FD_SET(fds[i].fd.socket, &rfds);
					if (fds[i].fd.socket > maxfd) maxfd = fds[i].fd.socket;
				}
				if (fds[i].events & LIBSSH2_POLLFD_POLLOUT) {
					FD_SET(fds[i].fd.socket, &wfds);
					if (fds[i].fd.socket > maxfd) maxfd = fds[i].fd.socket;
				}
				break;
			case LIBSSH2_POLLFD_CHANNEL:
				FD_SET(fds[i].fd.channel->session->socket_fd, &rfds);
				if (fds[i].fd.channel->session->socket_fd > maxfd) maxfd = fds[i].fd.channel->session->socket_fd;
				if (!session) session = fds[i].fd.channel->session;
				break;
			case LIBSSH2_POLLFD_LISTENER:
				FD_SET(fds[i].fd.listener->session->socket_fd, &rfds);
				if (fds[i].fd.listener->session->socket_fd > maxfd) maxfd = fds[i].fd.listener->session->socket_fd;
				if (!session) session = fds[i].fd.listener->session;
				break;
			default:
				if (session) libssh2_error(session, LIBSSH2_ERROR_INVALID_POLL_TYPE, "Invalid descriptor passed to libssh2_poll()", 0);
				return -1;
		}
	}
#else
	/* No select() or poll()
	 * no sockets sturcture to setup
	 */

	timeout = 0;
#endif /* HAVE_POLL or HAVE_SELECT */

	timeout_remaining = timeout;
	do {
#if defined(HAVE_POLL) || defined(HAVE_SELECT)
		int sysret;
#endif

		active_fds = 0;

		for (i = 0; i < nfds; i++) {
			if (fds[i].events != fds[i].revents) {
				switch (fds[i].type) {
					case LIBSSH2_POLLFD_CHANNEL:
						if ((fds[i].events & LIBSSH2_POLLFD_POLLIN) && /* Want to be ready for read */
							((fds[i].revents & LIBSSH2_POLLFD_POLLIN) == 0)) { /* Not yet known to be ready for read */
							fds[i].revents |= libssh2_poll_channel_read(fds[i].fd.channel, 0) ? LIBSSH2_POLLFD_POLLIN : 0;
						}
						if ((fds[i].events & LIBSSH2_POLLFD_POLLEXT) && /* Want to be ready for extended read */
							((fds[i].revents & LIBSSH2_POLLFD_POLLEXT) == 0)) { /* Not yet known to be ready for extended read */
							fds[i].revents |= libssh2_poll_channel_read(fds[i].fd.channel, 1) ? LIBSSH2_POLLFD_POLLEXT : 0;
						}
						if ((fds[i].events & LIBSSH2_POLLFD_POLLOUT) && /* Want to be ready for write */
							((fds[i].revents & LIBSSH2_POLLFD_POLLOUT) == 0)) { /* Not yet known to be ready for write */
							fds[i].revents |= libssh2_poll_channel_write(fds[i].fd.channel) ? LIBSSH2_POLLFD_POLLOUT : 0;
						}
						if (fds[i].fd.channel->remote.close || fds[i].fd.channel->local.close) {
							fds[i].revents |= LIBSSH2_POLLFD_CHANNEL_CLOSED;
						}
						if (fds[i].fd.channel->session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
							fds[i].revents |= LIBSSH2_POLLFD_CHANNEL_CLOSED | LIBSSH2_POLLFD_SESSION_CLOSED;
						}
						break;
					case LIBSSH2_POLLFD_LISTENER:
						if ((fds[i].events & LIBSSH2_POLLFD_POLLIN) && /* Want a connection */
							((fds[i].revents & LIBSSH2_POLLFD_POLLIN) == 0)) { /* No connections known of yet */
							fds[i].revents |= libssh2_poll_listener_queued(fds[i].fd.listener) ? LIBSSH2_POLLFD_POLLIN : 0;
						}
						if (fds[i].fd.listener->session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
							fds[i].revents |= LIBSSH2_POLLFD_LISTENER_CLOSED | LIBSSH2_POLLFD_SESSION_CLOSED;
						}
						break;
				}
			}
			if (fds[i].revents) {
				active_fds++;
			}
		}

		if (active_fds) {
			/* Don't block on the sockets if we have channels/listeners which are ready */
			timeout_remaining = 0;
		}

#ifdef HAVE_POLL

#ifdef HAVE_GETTIMEOFDAY
{
		struct timeval tv_begin, tv_end;

		gettimeofday((struct timeval *)&tv_begin, NULL);
		sysret = poll(sockets, nfds, timeout_remaining);
		gettimeofday((struct timeval *)&tv_end, NULL);
		timeout_remaining -= (tv_end.tv_sec - tv_begin.tv_sec) * 1000;
		timeout_remaining -= ceil((tv_end.tv_usec - tv_begin.tv_usec) / 1000);
}
#else
		/* If the platform doesn't support gettimeofday,
		 * then just make the call non-blocking and walk away
		 */
		sysret = poll(sockets, nfds, timeout_remaining);
		timeout_remaining = 0;
#endif /* HAVE_GETTIMEOFDAY */

		if (sysret > 0) {
			for (i = 0; i < nfds; i++) {
				switch (fds[i].type) {
					case LIBSSH2_POLLFD_SOCKET:
						fds[i].revents = sockets[i].revents;
						sockets[i].revents = 0; /* In case we loop again, be nice */
						if (fds[i].revents) {
							active_fds++;
						}
						break;
					case LIBSSH2_POLLFD_CHANNEL:
						if (sockets[i].events & POLLIN) {
							/* Spin session until no data available */
							while (libssh2_packet_read(fds[i].fd.channel->session, 0) > 0);
						}
						if (sockets[i].revents & POLLHUP) {
							fds[i].revents |= LIBSSH2_POLLFD_CHANNEL_CLOSED | LIBSSH2_POLLFD_SESSION_CLOSED;
						}
						sockets[i].revents = 0;
						break;
					case LIBSSH2_POLLFD_LISTENER:
						if (sockets[i].events & POLLIN) {
							/* Spin session until no data available */
							while (libssh2_packet_read(fds[i].fd.listener->session, 0) > 0);
						}
						if (sockets[i].revents & POLLHUP) {
							fds[i].revents |= LIBSSH2_POLLFD_LISTENER_CLOSED | LIBSSH2_POLLFD_SESSION_CLOSED;
						}
						sockets[i].revents = 0;
						break;
				}
			}
		}
#elif defined(HAVE_SELECT)
		tv.tv_sec = timeout_remaining / 1000;
		tv.tv_usec = (timeout_remaining % 1000) * 1000;
#ifdef HAVE_GETTIMEOFDAY
{
		struct timeval tv_begin, tv_end;

		gettimeofday((struct timeval *)&tv_begin, NULL);
		sysret = select(maxfd, &rfds, &wfds, NULL, &tv);
		gettimeofday((struct timeval *)&tv_end, NULL);

		timeout_remaining -= (tv_end.tv_sec - tv_begin.tv_sec) * 1000;
		timeout_remaining -= ceil((tv_end.tv_usec - tv_begin.tv_usec) / 1000);
}
#else
		/* If the platform doesn't support gettimeofday,
		 * then just make the call non-blocking and walk away
		 */
		sysret = select(maxfd, &rfds, &wfds, NULL, &tv);
		timeout_remaining = 0;
#endif

		if (sysret > 0) {
			for (i = 0; i < nfds; i++) {
				switch (fds[i].type) {
					case LIBSSH2_POLLFD_SOCKET:
						if (FD_ISSET(fds[i].fd.socket, &rfds)) {
							fds[i].revents |= LIBSSH2_POLLFD_POLLIN;
						}
						if (FD_ISSET(fds[i].fd.socket, &wfds)) {
							fds[i].revents |= LIBSSH2_POLLFD_POLLOUT;
						}
						if (fds[i].revents) {
							active_fds++;
						}
						break;
					case LIBSSH2_POLLFD_CHANNEL:
						if (FD_ISSET(fds[i].fd.channel->session->socket_fd, &rfds)) {
							/* Spin session until no data available */
							while (libssh2_packet_read(fds[i].fd.channel->session, 0) > 0);
						}
						break;
					case LIBSSH2_POLLFD_LISTENER:
						if (FD_ISSET(fds[i].fd.listener->session->socket_fd, &rfds)) {
							/* Spin session until no data available */
							while (libssh2_packet_read(fds[i].fd.listener->session, 0) > 0);
						}
						break;
				}
			}
		}
#endif /* else no select() or poll() -- timeout (and by extension timeout_remaining) will be equal to 0 */
	} while ((timeout_remaining > 0) && !active_fds);

	return active_fds;
}
/* }}} */

