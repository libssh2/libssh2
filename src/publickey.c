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
#include "libssh2_publickey.h"

struct _LIBSSH2_PUBLICKEY {
	LIBSSH2_CHANNEL *channel;
	unsigned long version;
};

#define LIBSSH2_PUBLICKEY_VERSION				2

/* Numericised response codes -- Not IETF standard, just a local representation */
#define LIBSSH2_PUBLICKEY_RESPONSE_STATUS		0
#define LIBSSH2_PUBLICKEY_RESPONSE_VERSION		1
#define LIBSSH2_PUBLICKEY_RESPONSE_PUBLICKEY	2

typedef struct _LIBSSH2_PUBLICKEY_CODE_LIST {
	int code;
	char *name;
	int name_len;
} LIBSSH2_PUBLICKEY_CODE_LIST;

static LIBSSH2_PUBLICKEY_CODE_LIST libssh2_publickey_response_codes[] = {
	{ LIBSSH2_PUBLICKEY_RESPONSE_STATUS, "status", sizeof("status") - 1 },
	{ LIBSSH2_PUBLICKEY_RESPONSE_VERSION, "version", sizeof("version") - 1 },
	{ LIBSSH2_PUBLICKEY_RESPONSE_PUBLICKEY, "publickey", sizeof("publickey") - 1 },
	{ 0, NULL, 0 }
};

/* PUBLICKEY status codes -- IETF defined */
#define LIBSSH2_PUBLICKEY_SUCCESS				0
#define LIBSSH2_PUBLICKEY_ACCESS_DENIED			1
#define LIBSSH2_PUBLICKEY_STORAGE_EXCEEDED		2
#define LIBSSH2_PUBLICKEY_VERSION_NOT_SUPPORTED	3
#define LIBSSH2_PUBLICKEY_KEY_NOT_FOUND			4
#define LIBSSH2_PUBLICKEY_KEY_NOT_SUPPORTED		5
#define LIBSSH2_PUBLICKEY_KEY_ALREADY_PRESENT	6
#define LIBSSH2_PUBLICKEY_GENERAL_FAILURE		7
#define LIBSSH2_PUBLICKEY_REQUEST_NOT_SUPPORTED	8

#define LIBSSH2_PUBLICKEY_STATUS_CODE_MAX		8

static LIBSSH2_PUBLICKEY_CODE_LIST libssh2_publickey_status_codes[] = {
	{ LIBSSH2_PUBLICKEY_SUCCESS,				"success",					sizeof("success") - 1 },
	{ LIBSSH2_PUBLICKEY_ACCESS_DENIED,			"access denied",			sizeof("access denied") - 1 },
	{ LIBSSH2_PUBLICKEY_STORAGE_EXCEEDED,		"storage exceeded",			sizeof("storage exceeded") - 1 },
	{ LIBSSH2_PUBLICKEY_VERSION_NOT_SUPPORTED,	"version not supported",	sizeof("version not supported") - 1 },
	{ LIBSSH2_PUBLICKEY_KEY_NOT_FOUND,			"key not found",			sizeof("key not found") - 1 },
	{ LIBSSH2_PUBLICKEY_KEY_NOT_SUPPORTED,		"key not supported",		sizeof("key not supported") - 1 },
	{ LIBSSH2_PUBLICKEY_KEY_ALREADY_PRESENT,	"key already present",		sizeof("key already present") - 1 },
	{ LIBSSH2_PUBLICKEY_GENERAL_FAILURE,		"general failure",			sizeof("general failure") - 1 },
	{ LIBSSH2_PUBLICKEY_REQUEST_NOT_SUPPORTED,	"request not supported",	sizeof("request not supported") - 1 },
	{ 0, NULL, 0 }
};

/* {{{ libssh2_publickey_status_error
 * Format an error message from a status code
 */
#define LIBSSH2_PUBLICKEY_STATUS_TEXT_START		"Publickey Subsystem Error: \""
#define LIBSSH2_PUBLICKEY_STATUS_TEXT_MID		"\" Server Resports: \""
#define LIBSSH2_PUBLICKEY_STATUS_TEXT_END		"\""
static void libssh2_publickey_status_error(LIBSSH2_PUBLICKEY *pkey, LIBSSH2_SESSION *session, int status, unsigned char *message, int message_len)
{
	char *status_text;
	int status_text_len;
	char *m, *s;
	int m_len;

	/* GENERAL_FAILURE got remapped between version 1 and 2 */
	if (status == 6 && pkey && pkey->version == 1) {
		status = 7;
	}

	if (status < 0 || status > LIBSSH2_PUBLICKEY_STATUS_CODE_MAX) {
		status_text = "unknown";
		status_text_len = sizeof("unknown") - 1;
	} else {
		status_text = libssh2_publickey_status_codes[status].name;
		status_text_len = libssh2_publickey_status_codes[status].name_len;
	}

	m_len = (sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_START) - 1) + status_text_len + 
			(sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_MID) - 1) + message_len +
			(sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_END) - 1);
	m = LIBSSH2_ALLOC(session, m_len + 1);
	if (!m) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for status message", 0);
		return;
	}
	s = m;
	memcpy(s, LIBSSH2_PUBLICKEY_STATUS_TEXT_START, sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_START) - 1);
															s += sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_START) - 1;
	memcpy(s, status_text, status_text_len);				s += status_text_len;
	memcpy(s, LIBSSH2_PUBLICKEY_STATUS_TEXT_MID, sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_MID) - 1);
															s += sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_MID) - 1;
	memcpy(s, message, message_len);						s += message_len;
	memcpy(s, LIBSSH2_PUBLICKEY_STATUS_TEXT_END, sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_END) - 1);
															s += sizeof(LIBSSH2_PUBLICKEY_STATUS_TEXT_END);
	libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, m, 1);
}
/* }}} */

/* {{{ libssh2_publickey_packet_receive
 * Read a packet from the subsystem
 */
static int libssh2_publickey_packet_receive(LIBSSH2_PUBLICKEY *pkey, unsigned char **data, unsigned long *data_len)
{
	LIBSSH2_CHANNEL *channel = pkey->channel;
	LIBSSH2_SESSION *session = channel->session;
	unsigned char buffer[4];
	unsigned long packet_len;
	unsigned char *packet;

	if (libssh2_channel_read(channel, (char *)buffer, 4) != 4) {
		libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Invalid response from publickey subsystem", 0);
		return -1;
	}

	packet_len = libssh2_ntohu32(buffer);
	packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate publickey response buffer", 0);
		return -1;
	}

	if (libssh2_channel_read(channel, (char *)packet, packet_len) != packet_len) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT, "Timeout waiting for publickey subsystem response packet", 0);
		LIBSSH2_FREE(session, packet);
		return -1;
	}

	*data = packet;
	*data_len = packet_len;

	return 0;
}
/* }}} */

/* {{{ libssh2_publickey_response_id
 * Translate a string response name to a numeric code
 * Data will be incremented by 4 + response_len on success only
 */
static int libssh2_publickey_response_id(unsigned char **pdata, int data_len)
{
	unsigned long response_len;
	unsigned char *data = *pdata;
	LIBSSH2_PUBLICKEY_CODE_LIST *codes = libssh2_publickey_response_codes;

	if (data_len < 4) {
		/* Malformed response */
		return -1;
	}
	response_len = libssh2_ntohu32(data);			data += 4;			data_len -= 4;
	if (data_len < response_len) {
		/* Malformed response */
		return -1;
	}

	while (codes->name) {
		if (codes->name_len == response_len &&
			strncmp(codes->name, (char *)data, response_len) == 0) {
			*pdata = data + response_len;
			return codes->code;
		}
		codes++;
	}

	return -1;
}
/* }}} */

/* {{{ libssh2_publickey_response_success
 * Generic helper routine to wait for success response and nothing else
 */
static int libssh2_publickey_response_success(LIBSSH2_PUBLICKEY *pkey)
{
	LIBSSH2_SESSION *session = pkey->channel->session;
	unsigned char *data, *s;
	unsigned long data_len;
	int response;

	while (1) {
		if (libssh2_publickey_packet_receive(pkey, &data, &data_len)) {
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT, "Timeout waiting for response from publickey subsystem", 0);
			return -1;
		}

		s = data;
		if ((response = libssh2_publickey_response_id(&s, data_len)) < 0) {
			libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Invalid publickey subsystem response code", 0);
			LIBSSH2_FREE(session, data);
			return -1;
		}

		switch (response) {
			case LIBSSH2_PUBLICKEY_RESPONSE_STATUS:
			/* Error, or processing complete */
			{
				unsigned long status, descr_len, lang_len;
				unsigned char *descr, *lang;
				
				status = libssh2_ntohu32(s);					s += 4;
				descr_len = libssh2_ntohu32(s);					s += 4;
				descr = s;										s += descr_len;
				lang_len = libssh2_ntohu32(s);					s += 4;
				lang = s;										s += lang_len;

				if (s > data + data_len) {
					libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Malformed publickey subsystem packet", 0);
					LIBSSH2_FREE(session, data);
					return -1;
				}

				if (status == LIBSSH2_PUBLICKEY_SUCCESS) {
					LIBSSH2_FREE(session, data);
					return 0;
				}

				libssh2_publickey_status_error(pkey, session, status, descr, descr_len);
				LIBSSH2_FREE(session, data);
				return -1;
			}
			default:
				/* Unknown/Unexpected */
				libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Unexpected publickey subsystem response, ignoring", 0);
				LIBSSH2_FREE(session, data);
				data = NULL;
		}
	}
	/* never reached, but include `return` to silence compiler warnings */
	return -1;
}
/* }}} */


/* *****************
   * Publickey API *
   ***************** */

/* {{{ libssh2_publickey_init
 * Startup the publickey subsystem
 */
LIBSSH2_API LIBSSH2_PUBLICKEY *libssh2_publickey_init(LIBSSH2_SESSION *session)
{
	LIBSSH2_PUBLICKEY *pkey = NULL;
	LIBSSH2_CHANNEL *channel = NULL;
	unsigned char buffer[19];
	/*	packet_len(4) + 
		version_len(4) + 
		"version"(7) + 
		version_num(4) */
	unsigned char *s, *data = NULL;
	unsigned long data_len;
	int response;

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Initializing publickey subsystem");
#endif

	channel = libssh2_channel_open_session(session);
	if (!channel) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE, "Unable to startup channel", 0);
		goto err_exit;
	}
	if (libssh2_channel_subsystem(channel, "publickey")) {
		libssh2_error(session, LIBSSH2_ERROR_CHANNEL_FAILURE, "Unable to request publickey subsystem", 0);
		goto err_exit;
	}

	libssh2_channel_set_blocking(channel, 1);
	libssh2_channel_handle_extended_data(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE);

	pkey = LIBSSH2_ALLOC(session, sizeof(LIBSSH2_PUBLICKEY));
	if (!pkey) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate a new publickey structure", 0);
		goto err_exit;
	}
	pkey->channel = channel;
	pkey->version = 0;

	s = buffer;
	libssh2_htonu32(s, 4 + (sizeof("version") - 1) + 4);	s += 4;
	libssh2_htonu32(s, sizeof("version") - 1);				s += 4;
	memcpy(s, "version", sizeof("version") - 1);			s += sizeof("version") - 1;
	libssh2_htonu32(s, LIBSSH2_PUBLICKEY_VERSION);			s += 4;

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Sending publickey version packet advertising version %d support", (int)LIBSSH2_PUBLICKEY_VERSION);
#endif
    if ((s - buffer) != libssh2_channel_write(channel, (char*)buffer, (s - buffer))) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send publickey version packet", 0);
		goto err_exit;
    }

	while (1) {
		if (libssh2_publickey_packet_receive(pkey, &data, &data_len)) {
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT, "Timeout waiting for response from publickey subsystem", 0);
			goto err_exit;
		}

		s = data;
		if ((response = libssh2_publickey_response_id(&s, data_len)) < 0) {
			libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Invalid publickey subsystem response code", 0);
			goto err_exit;
		}

		switch (response) {
			case LIBSSH2_PUBLICKEY_RESPONSE_STATUS:
			/* Error */
			{
				unsigned long status, descr_len, lang_len;
				unsigned char *descr, *lang;
				
				status = libssh2_ntohu32(s);					s += 4;
				descr_len = libssh2_ntohu32(s);					s += 4;
				descr = s;										s += descr_len;
				lang_len = libssh2_ntohu32(s);					s += 4;
				lang = s;										s += lang_len;

				if (s > data + data_len) {
					libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Malformed publickey subsystem packet", 0);
					goto err_exit;
				}

				libssh2_publickey_status_error(NULL, session, status, descr, descr_len);
				goto err_exit;
			}
			case LIBSSH2_PUBLICKEY_RESPONSE_VERSION:
				/* What we want */
				pkey->version = libssh2_ntohu32(s);
				if (pkey->version > LIBSSH2_PUBLICKEY_VERSION) {
#ifdef LIBSSH2_DEBUG_PUBLICKEY
					_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Truncating remote publickey version from %lu", pkey->version);
#endif
					pkey->version = LIBSSH2_PUBLICKEY_VERSION;
				}
#ifdef LIBSSH2_DEBUG_PUBLICKEY
				_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Enabling publickey subsystem version %lu", pkey->version);
#endif
				LIBSSH2_FREE(session, data);
				return pkey;
			default:
				/* Unknown/Unexpected */
				libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Unexpected publickey subsystem response, ignoring", 0);
				LIBSSH2_FREE(session, data);
				data = NULL;
		}
	}

	/* Never reached except by direct goto */
 err_exit:
	if (channel) {
		libssh2_channel_close(channel);
	}
	if (pkey) {
		LIBSSH2_FREE(session, pkey);
	}
	if (data) {
		LIBSSH2_FREE(session, data);
	}
	return NULL;
}
/* }}} */

/* {{{ libssh2_publickey_add_ex
 * Add a new public key entry
 */
LIBSSH2_API int libssh2_publickey_add_ex(LIBSSH2_PUBLICKEY *pkey, const unsigned char *name, unsigned long name_len,
															const unsigned char *blob, unsigned long blob_len, char overwrite,
															unsigned long num_attrs, libssh2_publickey_attribute attrs[])
{
	LIBSSH2_CHANNEL *channel = pkey->channel;
	LIBSSH2_SESSION *session = channel->session;
	unsigned char *packet = NULL, *s;
	unsigned long i, packet_len = 19 + name_len + blob_len;
	unsigned char *comment = NULL;
	unsigned long comment_len = 0;
	/*	packet_len(4) +
		add_len(4) +
		"add"(3) +
		name_len(4) +
		{name}
		blob_len(4) +
		{blob} */

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Adding %s pubickey", name);
#endif

	if (pkey->version == 1) {
		for(i = 0; i < num_attrs; i++) {
			/* Search for a comment attribute */
			if (attrs[i].name_len == (sizeof("comment") - 1) &&
				strncmp(attrs[i].name, "comment", sizeof("comment") - 1) == 0) {
				comment = (unsigned char *)attrs[i].value;
				comment_len = attrs[i].value_len;
				break;
			}
		}
		packet_len += 4 + comment_len;
	} else {
		packet_len += 5; /* overwrite(1) + attribute_count(4) */
		for(i = 0; i < num_attrs; i++) {
			packet_len += 9 + attrs[i].name_len + attrs[i].value_len;
			/* name_len(4) + value_len(4) + mandatory(1) */
		}
	}

	packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for publickey \"add\" packet", 0);
		return -1;
	}

	s = packet;
	libssh2_htonu32(s, packet_len - 4);						s += 4;
	libssh2_htonu32(s, sizeof("add") - 1);					s += 4;
	memcpy(s, "add", sizeof("add") - 1);					s += sizeof("add") - 1;
	if (pkey->version == 1) {
		libssh2_htonu32(s, comment_len);					s += 4;
		if (comment) {
			memcpy(s, comment, comment_len);				s += comment_len;
		}

		libssh2_htonu32(s, name_len);						s += 4;
		memcpy(s, name, name_len);							s += name_len;
		libssh2_htonu32(s, blob_len);						s += 4;
		memcpy(s, blob, blob_len);							s += blob_len;
	} else {
		/* Version == 2 */

		libssh2_htonu32(s, name_len);						s += 4;
		memcpy(s, name, name_len);							s += name_len;
		libssh2_htonu32(s, blob_len);						s += 4;
		memcpy(s, blob, blob_len);							s += blob_len;
		*(s++) = overwrite ? 0xFF : 0;
		libssh2_htonu32(s, num_attrs);						s += 4;
		for(i = 0; i < num_attrs; i++) {
			libssh2_htonu32(s, attrs[i].name_len);			s += 4;
			memcpy(s, attrs[i].name, attrs[i].name_len);	s += attrs[i].name_len;
			libssh2_htonu32(s, attrs[i].value_len);			s += 4;
			memcpy(s, attrs[i].value, attrs[i].value_len);	s += attrs[i].value_len;
			*(s++) = attrs[i].mandatory ? 0xFF : 0;
		}
	}

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Sending publickey \"add\" packet: type=%s blob_len=%ld num_attrs=%ld", name, blob_len, num_attrs);
#endif
    if ((s - packet) != libssh2_channel_write(channel, (char *)packet, (s - packet))) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send publickey add packet", 0);
		LIBSSH2_FREE(session, packet);
		return -1;
    }
	LIBSSH2_FREE(session, packet);
	packet = NULL;

	return libssh2_publickey_response_success(pkey);
}
/* }}} */

/* {{{ libssh2_publickey_remove_ex
 * Remove an existing publickey so that authentication can no longer be performed using it
 */
LIBSSH2_API int libssh2_publickey_remove_ex(LIBSSH2_PUBLICKEY *pkey, const unsigned char *name, unsigned long name_len,
                                                            const unsigned char *blob, unsigned long blob_len)
{
	LIBSSH2_CHANNEL *channel = pkey->channel;
	LIBSSH2_SESSION *session = channel->session;
	unsigned char *s, *packet = NULL;
	unsigned long packet_len = 22 + name_len + blob_len;
	/*	packet_len(4) + 
		remove_len(4) +
		"remove"(6) +
		name_len(4) +
		{name}
		blob_len(4) +
		{blob} */

	packet = LIBSSH2_ALLOC(session, packet_len);
	if (!packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for publickey \"remove\" packet", 0);
		return -1;
	}

	s = packet;
	libssh2_htonu32(s, packet_len - 4);							s += 4;
	libssh2_htonu32(s, sizeof("remove") - 1);					s += 4;
	memcpy(s, "remove", sizeof("remove") - 1);					s += sizeof("remove") - 1;
	libssh2_htonu32(s, name_len);								s += 4;
	memcpy(s, name, name_len);									s += name_len;
	libssh2_htonu32(s, blob_len);								s += 4;
	memcpy(s, blob, blob_len);									s += blob_len;

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Sending publickey \"remove\" packet: type=%s blob_len=%ld", name, blob_len);
#endif
    if ((s - packet) != libssh2_channel_write(channel, (char *)packet, (s - packet))) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send publickey remove packet", 0);
		LIBSSH2_FREE(session, packet);
		return -1;
    }
	LIBSSH2_FREE(session, packet);
	packet = NULL;

	return libssh2_publickey_response_success(pkey);
}
/* }}} */

/* {{{ libssh2_publickey_list_fetch
 * Fetch a list of supported public key from a server
 */
LIBSSH2_API int libssh2_publickey_list_fetch(LIBSSH2_PUBLICKEY *pkey, unsigned long *num_keys, libssh2_publickey_list **pkey_list)
{
	LIBSSH2_CHANNEL *channel = pkey->channel;
	LIBSSH2_SESSION *session = channel->session;
	libssh2_publickey_list *list = NULL;
	unsigned char *s, buffer[12], *data = NULL;
	unsigned long buffer_len = 12, keys = 0, max_keys = 0, data_len, i;
	/*	packet_len(4) +
		list_len(4) +
		"list"(4) */
	int response;

	s = buffer;
	libssh2_htonu32(s, buffer_len - 4);							s += 4;
	libssh2_htonu32(s, sizeof("list") - 1);						s += 4;
	memcpy(s, "list", sizeof("list") - 1);						s += sizeof("list") - 1;

#ifdef LIBSSH2_DEBUG_PUBLICKEY
	_libssh2_debug(session, LIBSSH2_DBG_PUBLICKEY, "Sending publickey \"list\" packet");
#endif
    if ((s - buffer) != libssh2_channel_write(channel, (char *)buffer, (s - buffer))) {
        libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send publickey list packet", 0);
		return -1;
    }

	while (1) {
		if (libssh2_publickey_packet_receive(pkey, &data, &data_len)) {
			libssh2_error(session, LIBSSH2_ERROR_SOCKET_TIMEOUT, "Timeout waiting for response from publickey subsystem", 0);
			goto err_exit;
		}

		s = data;
		if ((response = libssh2_publickey_response_id(&s, data_len)) < 0) {
			libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Invalid publickey subsystem response code", 0);
			goto err_exit;
		}

		switch (response) {
			case LIBSSH2_PUBLICKEY_RESPONSE_STATUS:
			/* Error, or processing complete */
			{
				unsigned long status, descr_len, lang_len;
				unsigned char *descr, *lang;
				
				status = libssh2_ntohu32(s);					s += 4;
				descr_len = libssh2_ntohu32(s);					s += 4;
				descr = s;										s += descr_len;
				lang_len = libssh2_ntohu32(s);					s += 4;
				lang = s;										s += lang_len;

				if (s > data + data_len) {
					libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Malformed publickey subsystem packet", 0);
					goto err_exit;
				}

				if (status == LIBSSH2_PUBLICKEY_SUCCESS) {
					LIBSSH2_FREE(session, data);
					*pkey_list = list;
					*num_keys = keys;
					return 0;
				}

				libssh2_publickey_status_error(pkey, session, status, descr, descr_len);
				goto err_exit;
			}
			case LIBSSH2_PUBLICKEY_RESPONSE_PUBLICKEY:
				/* What we want */
				if (keys >= max_keys) {
					/* Grow the key list if necessary */
					max_keys += 8;
					list = LIBSSH2_REALLOC(session, list, (max_keys + 1) * sizeof(libssh2_publickey_list));
					if (!list) {
						libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for publickey list", 0);
						goto err_exit;
					}
				}
				if (pkey->version == 1) {
					unsigned long comment_len;

					comment_len = libssh2_ntohu32(s);								s += 4;
					if (comment_len) {
						list[keys].num_attrs = 1;
						list[keys].attrs = LIBSSH2_ALLOC(session, sizeof(libssh2_publickey_attribute));
						if (!list[keys].attrs) {
							libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for publickey attributes", 0);
							goto err_exit;
						}
						list[keys].attrs[0].name = "comment";
						list[keys].attrs[0].name_len = sizeof("comment") - 1;
						list[keys].attrs[0].value = (char *)s;
						list[keys].attrs[0].value_len = comment_len;
						list[keys].attrs[0].mandatory = 0;

						s += comment_len;
					} else {
						list[keys].num_attrs = 0;
						list[keys].attrs = NULL;
					}
					list[keys].name_len = libssh2_ntohu32(s);						s += 4;
					list[keys].name = s;											s += list[keys].name_len;
					list[keys].blob_len = libssh2_ntohu32(s);						s += 4;
					list[keys].blob = s;											s += list[keys].blob_len;
				} else {
					/* Version == 2 */
					list[keys].name_len = libssh2_ntohu32(s);						s += 4;
					list[keys].name = s;											s += list[keys].name_len;
					list[keys].blob_len = libssh2_ntohu32(s);						s += 4;
					list[keys].blob = s;											s += list[keys].blob_len;
					list[keys].num_attrs = libssh2_ntohu32(s);						s += 4;
					if (list[keys].num_attrs) {
						list[keys].attrs = LIBSSH2_ALLOC(session, list[keys].num_attrs * sizeof(libssh2_publickey_attribute));
						if (!list[keys].attrs) {
							libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for publickey attributes", 0);
							goto err_exit;
						}
						for(i = 0; i < list[keys].num_attrs; i++) {
							list[keys].attrs[i].name_len = libssh2_ntohu32(s);			s += 4;
							list[keys].attrs[i].name = (char *)s;								s += list[keys].attrs[i].name_len;
							list[keys].attrs[i].value_len = libssh2_ntohu32(s);			s += 4;
							list[keys].attrs[i].value = (char *)s;								s += list[keys].attrs[i].value_len;
							list[keys].attrs[i].mandatory = 0;	/* actually an ignored value */
						}
					} else {
						list[keys].attrs = NULL;
					}
				}
				list[keys].packet = data; /* To be FREEd in libssh2_publickey_list_free() */
				keys++;

				list[keys].packet = NULL; /* Terminate the list */
				data = NULL;
				break;
			default:
				/* Unknown/Unexpected */
				libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_PROTOCOL, "Unexpected publickey subsystem response, ignoring", 0);
				LIBSSH2_FREE(session, data);
		}
	}

	/* Only reached via explicit goto */
 err_exit:
	if (data) {
		LIBSSH2_FREE(session, data);
	}
	if (list) {
		libssh2_publickey_list_free(pkey, list);
	}
	return -1;
}
/* }}} */

/* {{{ libssh2_publickey_list_free
 * Free a previously fetched list of public keys
 */
LIBSSH2_API void libssh2_publickey_list_free(LIBSSH2_PUBLICKEY *pkey, libssh2_publickey_list *pkey_list)
{
	LIBSSH2_SESSION *session = pkey->channel->session;
	libssh2_publickey_list *p = pkey_list;

	while (p->packet) {
		if (p->attrs) {
			LIBSSH2_FREE(session, p->attrs);
		}
		LIBSSH2_FREE(session, p->packet);
		p++;
	}

	LIBSSH2_FREE(session, pkey_list);
}
/* }}} */

/* {{{ libssh2_publickey_shutdown
 * Shutdown the publickey subsystem
 */
LIBSSH2_API void libssh2_publickey_shutdown(LIBSSH2_PUBLICKEY *pkey)
{
	LIBSSH2_SESSION *session = pkey->channel->session;

	libssh2_channel_free(pkey->channel);
	LIBSSH2_FREE(session, pkey);
}
/* }}} */
