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
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

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

		ret = read(session->socket_fd, &c, 1);

		if ((ret < 0) && (ret != EAGAIN)) {
			/* Some kinda error, but don't break for non-blocking issues */
			return 1;
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

	return (write(session->socket_fd, banner, banner_len) == banner_len) ? 0 : 1;
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
	}

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

	if (socket <= 0) {
		/* Did we forget something? */
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_NONE, "No socket provided", 0);
		return LIBSSH2_ERROR_SOCKET_NONE;
	}
	session->socket_fd = socket;

	/* TODO: Liveness check */

	if (libssh2_banner_receive(session)) {
		/* Unable to receive banner from remote */
		libssh2_error(session, LIBSSH2_ERROR_BANNER_NONE, "Timeout waiting for banner", 0);
		return LIBSSH2_ERROR_BANNER_NONE;
	}

	if (libssh2_banner_send(session)) {
		/* Unable to send banner? */
		libssh2_error(session, LIBSSH2_ERROR_BANNER_SEND, "Error sending banner to remote host", 0);
		return LIBSSH2_ERROR_BANNER_SEND;
	}

	if (libssh2_kex_exchange(session, 0)) {
		libssh2_error(session, LIBSSH2_ERROR_KEX_FAILURE, "Unable to exchange encryption keys", 0);
		return LIBSSH2_ERROR_KEX_FAILURE;
	}

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

	if (session->newkeys) {
		/* hostkey */
		if (session->hostkey && session->hostkey->dtor) {
			session->hostkey->dtor(session, &session->server_hostkey_abstract);
		}

		/* Client to Server */
		/* crypt */
		if (session->local.crypt) {
			if (session->local.crypt->flags & LIBSSH2_CRYPT_METHOD_FLAG_EVP) {
				if (session->local.crypt_abstract) {
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

	if (session->local.banner) {
		LIBSSH2_FREE(session, session->local.banner);
	}

	LIBSSH2_FREE(session, session);
}
/* }}} */

/* {{{ libssh2_session_disconnect_ex
 */
LIBSSH2_API void libssh2_session_disconnect_ex(LIBSSH2_SESSION *session, int reason, char *description, char *lang)
{
	unsigned char *data;
	unsigned long data_len, descr_len = 0, lang_len = 0;

	if (description) {
		descr_len = strlen(description);
	}
	if (lang) {
		lang_len = strlen(lang);
	}
	data_len = descr_len + lang_len + 13; /* packet_type(1) + reason code(4) + descr_len(4) + lang_len(4) */

	data = LIBSSH2_ALLOC(session, data_len);
	if (data) {
		unsigned char *s = data;

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
	}
}
/* }}} */

/* {{{ libssh2_session_methods
 * Return the currently active methods
 * NOTE: Currently lang_cs and lang_sc are ALWAYS set to empty string regardless of actual negotiation
 * Strings should NOT be freed
 */
LIBSSH2_API void libssh2_session_methods(LIBSSH2_SESSION *session,	char **kex,				char **hostkey,
																	char **crypt_cs,		char **crypt_sc,
																	char **mac_cs,			char **mac_sc,
																	char **comp_cs,			char **comp_sc,
																	char **lang_cs,			char **lang_sc)
{
	if (kex) {
		*kex = session->kex->name;
	}
	if (hostkey) {
		*hostkey = session->hostkey->name;
	}
	if (crypt_cs) {
		*crypt_cs = session->local.crypt->name;
	}
	if (crypt_sc) {
		*crypt_sc = session->remote.crypt->name;
	}
	if (mac_cs) {
		*mac_cs = session->local.mac->name;
	}
	if (mac_sc) {
		*mac_sc = session->remote.mac->name;
	}
	if (comp_cs) {
		*comp_cs = session->local.comp->name;
	}
	if (comp_sc) {
		*comp_sc = session->remote.comp->name;
	}
	if (lang_cs) {
		*lang_cs = "";
	}
	if (lang_sc) {
		*lang_sc = "";
	}
}
/* }}} */

/* {{{ libssh2_session_abstract
 * Retreive a pointer to the abstract property
 */
LIBSSH2_API void **libssh2_session_abstract(LIBSSH2_SESSION *session)
{
	return &session->abstract;
}
/* }}} */
