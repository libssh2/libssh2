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

/* TODO: Switch this to an inline and handle alloc() failures */
/* Helper macro called from libssh2_kex_method_diffie_hellman_group1_sha1_key_exchange */
#define LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(value, reqlen, version)	\
{	\
	libssh2_sha1_ctx hash;	\
	unsigned long len = 0;	\
	if (!(value)) {	\
		value = LIBSSH2_ALLOC(session, reqlen + SHA_DIGEST_LENGTH);	\
	}									\
	if (value)								\
		while (len < reqlen) {						\
			libssh2_sha1_init(&hash);				\
			libssh2_sha1_update(hash, k_value, k_value_len);	\
			libssh2_sha1_update(hash, h_sig_comp, SHA_DIGEST_LENGTH); \
			if (len > 0) {						\
				libssh2_sha1_update(hash, value, len);		\
			}	else {						\
				libssh2_sha1_update(hash, (version), 1);	\
				libssh2_sha1_update(hash, session->session_id, session->session_id_len); \
			}							\
			libssh2_sha1_final(hash, (value) + len);		\
			len += SHA_DIGEST_LENGTH;				\
		}								\
}

/* {{{ libssh2_kex_method_diffie_hellman_groupGP_sha1_key_exchange
 * Diffie Hellman Key Exchange, Group Agnostic
 */
static int libssh2_kex_method_diffie_hellman_groupGP_sha1_key_exchange(LIBSSH2_SESSION *session, _libssh2_bn *g, _libssh2_bn *p, int group_order,
																		unsigned char packet_type_init, unsigned char packet_type_reply,
																		unsigned char *midhash, unsigned long midhash_len)
{
	unsigned char *e_packet = NULL, *s_packet = NULL, *tmp, h_sig_comp[SHA_DIGEST_LENGTH], c;
	unsigned long e_packet_len, s_packet_len, tmp_len;
	int ret = 0;
	_libssh2_bn_ctx *ctx = _libssh2_bn_ctx_new();
	_libssh2_bn *x = _libssh2_bn_init(); /* Random from client */
	_libssh2_bn *e = _libssh2_bn_init(); /* g^x mod p */
	_libssh2_bn *f = _libssh2_bn_init(); /* g^(Random from server) mod p */
	_libssh2_bn *k = _libssh2_bn_init(); /* The shared secret: f^x mod p */
	unsigned char *s, *f_value, *k_value = NULL, *h_sig;
	unsigned long f_value_len, k_value_len, h_sig_len;
	libssh2_sha1_ctx exchange_hash;
	int rc;

	/* Generate x and e */
	_libssh2_bn_rand(x, group_order, 0, -1);
	_libssh2_bn_mod_exp(e, g, x, p, ctx);

	/* Send KEX init */
	e_packet_len = _libssh2_bn_bytes(e) + 6; /* packet_type(1) + String Length(4) + leading 0(1) */
	if (_libssh2_bn_bits(e) % 8) {
		/* Leading 00 not needed */
		e_packet_len--;
	}
	e_packet = LIBSSH2_ALLOC(session, e_packet_len);
	if (!e_packet) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Out of memory error", 0);
		ret = -1;
		goto clean_exit;
	}
	e_packet[0] = packet_type_init;
	libssh2_htonu32(e_packet + 1, e_packet_len - 5);
	if (_libssh2_bn_bits(e) % 8) {
		_libssh2_bn_to_bin(e, e_packet + 5);
	} else {
		e_packet[5] = 0;
		_libssh2_bn_to_bin(e, e_packet + 6);
	}

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sending KEX packet %d", (int)packet_type_init);
	rc = libssh2_packet_write(session, e_packet, e_packet_len);
	if (rc) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send KEX init message", 0);
		ret = -11;
		goto clean_exit;
	}

	if (session->burn_optimistic_kexinit) {
		/* The first KEX packet to come along will be the guess initially sent by the server
		 * That guess turned out to be wrong so we need to silently ignore it */
		int burn_type;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Waiting for badly guessed KEX packet (to be ignored)");
		burn_type = libssh2_packet_burn(session);
		if (burn_type <= 0) {
			/* Failed to receive a packet */
			ret = -1;
			goto clean_exit;
		}
		session->burn_optimistic_kexinit = 0;

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Burnt packet of type: %02x", (unsigned int)burn_type);
	}

	/* Wait for KEX reply */
	rc = libssh2_packet_require(session, packet_type_reply, &s_packet,
				    &s_packet_len);
	if (rc) {
		libssh2_error(session, LIBSSH2_ERROR_TIMEOUT,
			      "Timed out waiting for KEX reply", 0);
		ret = -1;
		goto clean_exit;
	}

	/* Parse KEXDH_REPLY */
	s = s_packet + 1;

	session->server_hostkey_len = libssh2_ntohu32(s);			s += 4;
	session->server_hostkey = LIBSSH2_ALLOC(session, session->server_hostkey_len);
	if (!session->server_hostkey) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory for a copy of the host key", 0);
		ret = -1;
		goto clean_exit;
	}
	memcpy(session->server_hostkey, s, session->server_hostkey_len);
	s += session->server_hostkey_len;

#if LIBSSH2_MD5
{
	libssh2_md5_ctx fingerprint_ctx;

	libssh2_md5_init(&fingerprint_ctx);
	libssh2_md5_update(fingerprint_ctx, session->server_hostkey, session->server_hostkey_len);
	libssh2_md5_final(fingerprint_ctx, session->server_hostkey_md5);
}
#ifdef LIBSSH2DEBUG
{
	char fingerprint[50], *fprint = fingerprint;
	int i;
	for(i = 0; i < 16; i++, fprint += 3) {
		snprintf(fprint, 4, "%02x:", session->server_hostkey_md5[i]);
	}
	*(--fprint) = '\0';
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Server's MD5 Fingerprint: %s", fingerprint);
}
#endif /* LIBSSH2DEBUG */
#endif /* ! LIBSSH2_MD5 */

{
	libssh2_sha1_ctx fingerprint_ctx;

	libssh2_sha1_init(&fingerprint_ctx);
	libssh2_sha1_update (fingerprint_ctx, session->server_hostkey, session->server_hostkey_len);
	libssh2_sha1_final(fingerprint_ctx, session->server_hostkey_sha1);
}
#ifdef LIBSSH2DEBUG
{
	char fingerprint[64], *fprint = fingerprint;
	int i;
	for(i = 0; i < 20; i++, fprint += 3) {
		snprintf(fprint, 4, "%02x:", session->server_hostkey_sha1[i]);
	}
	*(--fprint) = '\0';
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Server's SHA1 Fingerprint: %s", fingerprint);
}
#endif /* LIBSSH2DEBUG */

	if (session->hostkey->init(session, session->server_hostkey, session->server_hostkey_len, &session->server_hostkey_abstract)) {
		libssh2_error(session, LIBSSH2_ERROR_HOSTKEY_INIT, "Unable to initialize hostkey importer", 0);
		ret = -1;
		goto clean_exit;
	}

	f_value_len = libssh2_ntohu32(s);							s += 4;
	f_value = s;												s += f_value_len;
	_libssh2_bn_from_bin(f, f_value_len, f_value);

	h_sig_len = libssh2_ntohu32(s);								s += 4;
	h_sig = s;

	/* Compute the shared secret */
	_libssh2_bn_mod_exp(k, f, x, p, ctx);
	k_value_len = _libssh2_bn_bytes(k) + 5;
	if (_libssh2_bn_bits(k) % 8) {
		/* don't need leading 00 */
		k_value_len--;
	}
	k_value = LIBSSH2_ALLOC(session, k_value_len);
	if (!k_value) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate buffer for K", 0);
		ret = -1;
		goto clean_exit;
	}
	libssh2_htonu32(k_value, k_value_len - 4);
	if (_libssh2_bn_bits(k) % 8) {
		_libssh2_bn_to_bin(k, k_value + 4);
	} else {
		k_value[4] = 0;
		_libssh2_bn_to_bin(k, k_value + 5);
	}

	libssh2_sha1_init(&exchange_hash);
	if (session->local.banner) {
		libssh2_htonu32(h_sig_comp,
				strlen((char *)session->local.banner) - 2);
		libssh2_sha1_update(exchange_hash, h_sig_comp, 4);
		libssh2_sha1_update(exchange_hash, (char *)session->local.banner,
			    strlen((char *)session->local.banner) - 2);
	} else {
		libssh2_htonu32(h_sig_comp, sizeof(LIBSSH2_SSH_DEFAULT_BANNER) - 1);
		libssh2_sha1_update(exchange_hash, h_sig_comp, 4);
		libssh2_sha1_update(exchange_hash, LIBSSH2_SSH_DEFAULT_BANNER,
			    sizeof(LIBSSH2_SSH_DEFAULT_BANNER) - 1);
	}

	libssh2_htonu32(h_sig_comp, strlen((char *)session->remote.banner));
	libssh2_sha1_update(exchange_hash, h_sig_comp, 4);
	libssh2_sha1_update(exchange_hash, session->remote.banner,
		    strlen((char *)session->remote.banner));

	libssh2_htonu32(h_sig_comp, session->local.kexinit_len);
	libssh2_sha1_update(exchange_hash,		h_sig_comp,							4);
	libssh2_sha1_update(exchange_hash,		session->local.kexinit,				session->local.kexinit_len);

	libssh2_htonu32(h_sig_comp, session->remote.kexinit_len);
	libssh2_sha1_update(exchange_hash,		h_sig_comp,							4);
	libssh2_sha1_update(exchange_hash,		session->remote.kexinit,			session->remote.kexinit_len);

	libssh2_htonu32(h_sig_comp, session->server_hostkey_len);
	libssh2_sha1_update(exchange_hash,		h_sig_comp,							4);
	libssh2_sha1_update(exchange_hash,		session->server_hostkey,			session->server_hostkey_len);

	if (packet_type_init == SSH_MSG_KEX_DH_GEX_INIT) {
		/* diffie-hellman-group-exchange hashes additional fields */
#ifdef LIBSSH2_DH_GEX_NEW
		libssh2_htonu32(h_sig_comp,		LIBSSH2_DH_GEX_MINGROUP);
		libssh2_htonu32(h_sig_comp + 4,	LIBSSH2_DH_GEX_OPTGROUP);
		libssh2_htonu32(h_sig_comp + 8, LIBSSH2_DH_GEX_MAXGROUP);
		libssh2_sha1_update(exchange_hash,	h_sig_comp,							12);
#else
		libssh2_htonu32(h_sig_comp,		LIBSSH2_DH_GEX_OPTGROUP);
		libssh2_sha1_update(exchange_hash,	h_sig_comp,							4);
#endif
	}

	if (midhash) {
		libssh2_sha1_update(exchange_hash, midhash,							midhash_len);
	}

	libssh2_sha1_update(exchange_hash,		e_packet + 1,						e_packet_len - 1);

	libssh2_htonu32(h_sig_comp, f_value_len);
	libssh2_sha1_update(exchange_hash,		h_sig_comp,							4);
	libssh2_sha1_update(exchange_hash,		f_value,							f_value_len);

	libssh2_sha1_update(exchange_hash,		k_value,							k_value_len);

	libssh2_sha1_final(exchange_hash, h_sig_comp);

	if (session->hostkey->sig_verify(session, h_sig, h_sig_len, h_sig_comp, 20, &session->server_hostkey_abstract)) {
		libssh2_error(session, LIBSSH2_ERROR_HOSTKEY_SIGN, "Unable to verify hostkey signature", 0);
		ret = -1;
		goto clean_exit;
	}

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sending NEWKEYS message");
	c = SSH_MSG_NEWKEYS;
	if (libssh2_packet_write(session, &c, 1)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send NEWKEYS message", 0);
		ret = -1;
		goto clean_exit;
	}

	if (libssh2_packet_require(session, SSH_MSG_NEWKEYS, &tmp, &tmp_len)) {
		libssh2_error(session, LIBSSH2_ERROR_TIMEOUT, "Timed out waiting for NEWKEYS", 0);
		ret = -1;
		goto clean_exit;
	}
	/* The first key exchange has been performed, switch to active crypt/comp/mac mode */
	session->state |= LIBSSH2_STATE_NEWKEYS;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Received NEWKEYS message");

	/* This will actually end up being just packet_type(1) for this packet type anyway */
	LIBSSH2_FREE(session, tmp);

	if (!session->session_id) {
		session->session_id = LIBSSH2_ALLOC(session, SHA_DIGEST_LENGTH);
		if (!session->session_id) {
			ret = -1;
			goto clean_exit;
		}
		memcpy(session->session_id, h_sig_comp, SHA_DIGEST_LENGTH);
		session->session_id_len = SHA_DIGEST_LENGTH;
		_libssh2_debug(session, LIBSSH2_DBG_KEX,
			       "session_id calculated");
	}

	/* Cleanup any existing cipher */
	if (session->local.crypt->dtor) {
		session->local.crypt->dtor(session, &session->local.crypt_abstract);
	}

	/* Calculate IV/Secret/Key for each direction */
	if (session->local.crypt->init) {
		unsigned char *iv = NULL, *secret = NULL;
		int free_iv = 0, free_secret = 0;

		LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(iv, session->local.crypt->iv_len, "A");
		if (!iv) {
		  ret = -1;
		  goto clean_exit;
		}
		LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(secret, session->local.crypt->secret_len, "C");
		if (!secret) {
		  LIBSSH2_FREE(session, iv);
		  ret = -1;
		  goto clean_exit;
		}
		if (session->local.crypt->init(session, session->local.crypt, iv, &free_iv, secret, &free_secret, 1, &session->local.crypt_abstract)) {
		  LIBSSH2_FREE(session, iv);
		  LIBSSH2_FREE(session, secret);
		  ret = -1;
		  goto clean_exit;
		}

		if (free_iv) {
			memset(iv, 0, session->local.crypt->iv_len);
			LIBSSH2_FREE(session, iv);
		}

		if (free_secret) {
			memset(secret, 0, session->local.crypt->secret_len);
			LIBSSH2_FREE(session, secret);
		}
	}
        _libssh2_debug(session, LIBSSH2_DBG_KEX,
	       "Client to Server IV and Key calculated");

	if (session->remote.crypt->dtor) {
		/* Cleanup any existing cipher */
		session->remote.crypt->dtor(session, &session->remote.crypt_abstract);
	}

	if (session->remote.crypt->init) {
		unsigned char *iv = NULL, *secret = NULL;
		int free_iv = 0, free_secret = 0;

		LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(iv, session->remote.crypt->iv_len, "B");
		if (!iv) {
		  ret = -1;
		  goto clean_exit;
		}
		LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(secret, session->remote.crypt->secret_len, "D");
		if (!secret) {
		  LIBSSH2_FREE(session, iv);
		  ret = -1;
		  goto clean_exit;
		}
		if (session->remote.crypt->init(session, session->remote.crypt, iv, &free_iv, secret, &free_secret, 0, &session->remote.crypt_abstract)) {
		  LIBSSH2_FREE(session, iv);
		  LIBSSH2_FREE(session, secret);
		  ret = -1;
		  goto clean_exit;
		}

		if (free_iv) {
			memset(iv, 0, session->remote.crypt->iv_len);
			LIBSSH2_FREE(session, iv);
		}

		if (free_secret) {
			memset(secret, 0, session->remote.crypt->secret_len);
			LIBSSH2_FREE(session, secret);
		}
	}
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Server to Client IV and Key calculated");

	if (session->local.mac->dtor) {
		session->local.mac->dtor(session, &session->local.mac_abstract);
	}

	if (session->local.mac->init) {
		unsigned char *key = NULL;
		int free_key = 0;

		LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(key, session->local.mac->key_len, "E");
		if (!key) {
		  ret = -1;
		  goto clean_exit;
		}
		session->local.mac->init(session, key, &free_key, &session->local.mac_abstract);

		if (free_key) {
			memset(key, 0, session->local.mac->key_len);
			LIBSSH2_FREE(session, key);
		}
	}
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Client to Server HMAC Key calculated");

	if (session->remote.mac->dtor) {
		session->remote.mac->dtor(session, &session->remote.mac_abstract);
	}

	if (session->remote.mac->init) {
		unsigned char *key = NULL;
		int free_key = 0;

		LIBSSH2_KEX_METHOD_DIFFIE_HELLMAN_SHA1_HASH(key, session->remote.mac->key_len, "F");
		if (!key) {
		  ret = -1;
		  goto clean_exit;
		}
		session->remote.mac->init(session, key, &free_key, &session->remote.mac_abstract);

		if (free_key) {
			memset(key, 0, session->remote.mac->key_len);
			LIBSSH2_FREE(session, key);
		}
	}
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Server to Client HMAC Key calculated");

 clean_exit:
	_libssh2_bn_free(x);
	_libssh2_bn_free(e);
	_libssh2_bn_free(f);
	_libssh2_bn_free(k);
	_libssh2_bn_ctx_free(ctx);

	if (e_packet) {
		LIBSSH2_FREE(session, e_packet);
	}

	if (s_packet) {
		LIBSSH2_FREE(session, s_packet);
	}

	if (k_value) {
		LIBSSH2_FREE(session, k_value);
	}

	if (session->server_hostkey) {
		LIBSSH2_FREE(session, session->server_hostkey);
		session->server_hostkey = NULL;
	}

	return ret;
}
/* }}} */

/* {{{ libssh2_kex_method_diffie_hellman_group1_sha1_key_exchange
 * Diffie-Hellman Group1 (Actually Group2) Key Exchange using SHA1
 */
static int libssh2_kex_method_diffie_hellman_group1_sha1_key_exchange(LIBSSH2_SESSION *session)
{
	static const unsigned char p_value[128] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
		0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
		0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
		0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
		0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	/* g == 2 */
	_libssh2_bn *p = _libssh2_bn_init(); /* SSH2 defined value (p_value) */
	_libssh2_bn *g = _libssh2_bn_init(); /* SSH2 defined value (2) */
	int ret;

	/* Initialize P and G */
	_libssh2_bn_set_word(g, 2);
	_libssh2_bn_from_bin(p, 128, p_value);

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Initiating Diffie-Hellman Group1 Key Exchange");

	ret = libssh2_kex_method_diffie_hellman_groupGP_sha1_key_exchange(session, g, p, 128, SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY, NULL, 0);

	_libssh2_bn_free(p);
	_libssh2_bn_free(g);

	return ret;
}
/* }}} */

/* {{{ libssh2_kex_method_diffie_hellman_group14_sha1_key_exchange
 * Diffie-Hellman Group14 Key Exchange using SHA1
 */
static int libssh2_kex_method_diffie_hellman_group14_sha1_key_exchange(LIBSSH2_SESSION *session)
{
	static const unsigned char p_value[256] = {
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
		0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
		0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
		0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
		0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
		0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
		0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
		0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
		0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
		0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
		0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
		0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
		0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
		0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C,
		0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03,
		0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
		0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
		0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
		0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5,
		0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	/* g == 2 */
	_libssh2_bn *p = _libssh2_bn_init(); /* SSH2 defined value (p_value) */
	_libssh2_bn *g = _libssh2_bn_init(); /* SSH2 defined value (2) */
	int ret;

	/* Initialize P and G */
	_libssh2_bn_set_word(g, 2);
	_libssh2_bn_from_bin(p, 256, p_value);

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Initiating Diffie-Hellman Group14 Key Exchange");
	ret = libssh2_kex_method_diffie_hellman_groupGP_sha1_key_exchange(session, g, p, 256, SSH_MSG_KEXDH_INIT, SSH_MSG_KEXDH_REPLY, NULL, 0);

	_libssh2_bn_free(p);
	_libssh2_bn_free(g);

	return ret;
}
/* }}} */

/* {{{ libssh2_kex_method_diffie_hellman_group_exchange_sha1_key_exchange
 * Diffie-Hellman Group Exchange Key Exchange using SHA1
 * Negotiates random(ish) group for secret derivation
 */
static int libssh2_kex_method_diffie_hellman_group_exchange_sha1_key_exchange(LIBSSH2_SESSION *session)
{
	unsigned char request[13], *s, *data;
	unsigned long data_len, p_len, g_len, request_len;
	_libssh2_bn *p = _libssh2_bn_init ();
	_libssh2_bn *g = _libssh2_bn_init ();
	int ret;

	/* Ask for a P and G pair */
#ifdef LIBSSH2_DH_GEX_NEW
	request[0] = SSH_MSG_KEX_DH_GEX_REQUEST;
	libssh2_htonu32(request + 1, LIBSSH2_DH_GEX_MINGROUP);
	libssh2_htonu32(request + 5, LIBSSH2_DH_GEX_OPTGROUP);
	libssh2_htonu32(request	+ 9, LIBSSH2_DH_GEX_MAXGROUP);
	request_len = 13;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Initiating Diffie-Hellman Group-Exchange (New Method)");
#else
	request[0] = SSH_MSG_KEX_DH_GEX_REQUEST_OLD;
	libssh2_htonu32(request + 1, LIBSSH2_DH_GEX_OPTGROUP);
	request_len = 5;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Initiating Diffie-Hellman Group-Exchange (Old Method)");
#endif

	if (libssh2_packet_write(session, request, request_len)) {
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send Group Exchange Request", 0);
		ret = -1;
		goto dh_gex_clean_exit;
	}

	if (libssh2_packet_require(session, SSH_MSG_KEX_DH_GEX_GROUP, &data, &data_len)) {
		libssh2_error(session, LIBSSH2_ERROR_TIMEOUT, "Timeout waiting for GEX_GROUP reply", 0);
		ret = -1;
		goto dh_gex_clean_exit;
	}

	s = data + 1;
	p_len = libssh2_ntohu32(s);						s += 4;
	_libssh2_bn_from_bin(p, p_len, s);					s += p_len;

	g_len = libssh2_ntohu32(s);						s += 4;
	_libssh2_bn_from_bin(g, g_len, s);					s += g_len;

	ret = libssh2_kex_method_diffie_hellman_groupGP_sha1_key_exchange(session, g, p, p_len, SSH_MSG_KEX_DH_GEX_INIT, SSH_MSG_KEX_DH_GEX_REPLY, data + 1, data_len - 1);

	LIBSSH2_FREE(session, data);

 dh_gex_clean_exit:
	_libssh2_bn_free(g);
	_libssh2_bn_free(p);

	return ret;
}
/* }}} */

#define LIBSSH2_KEX_METHOD_FLAG_REQ_ENC_HOSTKEY		0x0001
#define LIBSSH2_KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY	0x0002

const LIBSSH2_KEX_METHOD libssh2_kex_method_diffie_helman_group1_sha1 = {
	"diffie-hellman-group1-sha1",
	libssh2_kex_method_diffie_hellman_group1_sha1_key_exchange,
	LIBSSH2_KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY,
};

const LIBSSH2_KEX_METHOD libssh2_kex_method_diffie_helman_group14_sha1 = {
	"diffie-hellman-group14-sha1",
	libssh2_kex_method_diffie_hellman_group14_sha1_key_exchange,
	LIBSSH2_KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY,
};

const LIBSSH2_KEX_METHOD libssh2_kex_method_diffie_helman_group_exchange_sha1 = {
	"diffie-hellman-group-exchange-sha1",
	libssh2_kex_method_diffie_hellman_group_exchange_sha1_key_exchange,
	LIBSSH2_KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY,
};

const LIBSSH2_KEX_METHOD *libssh2_kex_methods[] = {
	&libssh2_kex_method_diffie_helman_group14_sha1,
	&libssh2_kex_method_diffie_helman_group_exchange_sha1,
	&libssh2_kex_method_diffie_helman_group1_sha1,
	NULL
};

typedef struct _LIBSSH2_COMMON_METHOD {
	const char *name;
} LIBSSH2_COMMON_METHOD;

/* {{{ libssh2_kex_method_strlen
 * Calculate the length of a particular method list's resulting string
 * Includes SUM(strlen() of each individual method plus 1 (for coma)) - 1 (because the last coma isn't used)
 * Another sign of bad coding practices gone mad.  Pretend you don't see this.
 */
static size_t libssh2_kex_method_strlen(LIBSSH2_COMMON_METHOD **method)
{
	size_t len = 0;

	if (!method || !*method) {
		return 0;
	}

	while (*method && (*method)->name) {
		len += strlen((*method)->name) + 1;
		method++;
	}

	return len - 1;
}
/* }}} */

/* {{{ libssh2_kex_method_list
 * Generate formatted preference list in buf
 */
static size_t libssh2_kex_method_list(unsigned char *buf, size_t list_strlen, LIBSSH2_COMMON_METHOD **method)
{
	libssh2_htonu32(buf, list_strlen);
	buf += 4;

	if (!method || !*method) {
		return 4;
	}

	while (*method && (*method)->name) {
		int mlen = strlen((*method)->name);
		memcpy(buf, (*method)->name, mlen);
		buf += mlen;
		*(buf++) = ',';
		method++;
	}

	return list_strlen + 4;
}
/* }}} */

#define LIBSSH2_METHOD_PREFS_LEN(prefvar, defaultvar)	((prefvar) ? strlen(prefvar) : libssh2_kex_method_strlen((LIBSSH2_COMMON_METHOD**)(defaultvar)))
#define LIBSSH2_METHOD_PREFS_STR(buf, prefvarlen, prefvar, defaultvar)	\
	if (prefvar) {	\
		libssh2_htonu32((buf), (prefvarlen));	\
		buf += 4;	\
		memcpy((buf), (prefvar), (prefvarlen));	\
		buf += (prefvarlen);	\
	} else {	\
		buf += libssh2_kex_method_list((buf), (prefvarlen),	(LIBSSH2_COMMON_METHOD**)(defaultvar));	\
	}

/* {{{ libssh2_kexinit
 * Send SSH_MSG_KEXINIT packet
 */
static int libssh2_kexinit(LIBSSH2_SESSION *session)
{
	size_t data_len = 62; /* packet_type(1) + cookie(16) + first_packet_follows(1) + reserved(4) + length longs(40) */
	size_t kex_len,			hostkey_len = 0;
	size_t crypt_cs_len,	crypt_sc_len;
	size_t comp_cs_len,		comp_sc_len;
	size_t mac_cs_len,		mac_sc_len;
	size_t lang_cs_len,		lang_sc_len;
	unsigned char *data, *s;

	kex_len			= LIBSSH2_METHOD_PREFS_LEN(session->kex_prefs,			libssh2_kex_methods);
	hostkey_len		= LIBSSH2_METHOD_PREFS_LEN(session->hostkey_prefs,		libssh2_hostkey_methods());
	crypt_cs_len	= LIBSSH2_METHOD_PREFS_LEN(session->local.crypt_prefs,	libssh2_crypt_methods());
	crypt_sc_len	= LIBSSH2_METHOD_PREFS_LEN(session->remote.crypt_prefs,	libssh2_crypt_methods());
	mac_cs_len		= LIBSSH2_METHOD_PREFS_LEN(session->local.mac_prefs,	libssh2_mac_methods());
	mac_sc_len		= LIBSSH2_METHOD_PREFS_LEN(session->remote.mac_prefs,	libssh2_mac_methods());
	comp_cs_len		= LIBSSH2_METHOD_PREFS_LEN(session->local.comp_prefs,	libssh2_comp_methods());
	comp_sc_len		= LIBSSH2_METHOD_PREFS_LEN(session->remote.comp_prefs,	libssh2_comp_methods());
	lang_cs_len		= LIBSSH2_METHOD_PREFS_LEN(session->local.lang_prefs,	NULL);
	lang_sc_len		= LIBSSH2_METHOD_PREFS_LEN(session->remote.lang_prefs,	NULL);

	data_len += kex_len			+ hostkey_len + \
				crypt_cs_len	+ crypt_sc_len + \
				comp_cs_len		+ comp_sc_len + \
				mac_cs_len		+ mac_sc_len + \
				lang_cs_len		+ lang_sc_len;

	s = data = LIBSSH2_ALLOC(session, data_len);
	if (!data) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Unable to allocate memory", 0);
		return -1;
	}

	*(s++) = SSH_MSG_KEXINIT;

	libssh2_random(s, 16);
	s += 16;

	/* Ennumerating through these lists twice is probably (certainly?) inefficient from a CPU standpoint, but it saves multiple malloc/realloc calls */
	LIBSSH2_METHOD_PREFS_STR(s, kex_len,		session->kex_prefs,				libssh2_kex_methods);
	LIBSSH2_METHOD_PREFS_STR(s, hostkey_len,	session->hostkey_prefs,			libssh2_hostkey_methods());
	LIBSSH2_METHOD_PREFS_STR(s, crypt_cs_len,	session->local.crypt_prefs,		libssh2_crypt_methods());
	LIBSSH2_METHOD_PREFS_STR(s, crypt_sc_len,	session->remote.crypt_prefs,	libssh2_crypt_methods());
	LIBSSH2_METHOD_PREFS_STR(s, mac_cs_len,		session->local.mac_prefs,		libssh2_mac_methods());
	LIBSSH2_METHOD_PREFS_STR(s, mac_sc_len,		session->remote.mac_prefs,		libssh2_mac_methods());
	LIBSSH2_METHOD_PREFS_STR(s, comp_cs_len,	session->local.comp_prefs,		libssh2_comp_methods());
	LIBSSH2_METHOD_PREFS_STR(s, comp_sc_len,	session->remote.comp_prefs,		libssh2_comp_methods());
	LIBSSH2_METHOD_PREFS_STR(s, lang_cs_len,	session->local.lang_prefs,		NULL);
	LIBSSH2_METHOD_PREFS_STR(s, lang_sc_len,	session->remote.lang_prefs,		NULL);

	/* No optimistic KEX packet follows */
	/* Deal with optimistic packets
	 * session->flags |= KEXINIT_OPTIMISTIC
	 * session->flags |= KEXINIT_METHODSMATCH
	 */
	*(s++) = 0;

	/* Reserved == 0 */
	*(s++) = 0;
	*(s++) = 0;
	*(s++) = 0;
	*(s++) = 0;

#ifdef LIBSSH2DEBUG
{
	/* Funnily enough, they'll all "appear" to be '\0' terminated */
	unsigned char *p = data + 21; /* type(1) + cookie(16) + len(4) */

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent KEX: %s", p);				p += kex_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent HOSTKEY: %s", p);			p += hostkey_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent CRYPT_CS: %s", p);			p += crypt_cs_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent CRYPT_SC: %s", p);			p += crypt_sc_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent MAC_CS: %s", p);				p += mac_cs_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent MAC_SC: %s", p);				p += mac_sc_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent COMP_CS: %s", p);			p += comp_cs_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent COMP_SC: %s", p);			p += comp_sc_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent LANG_CS: %s", p);			p += lang_cs_len + 4;
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Sent LANG_SC: %s", p);			p += lang_sc_len + 4;
}
#endif /* LIBSSH2DEBUG */
	if (libssh2_packet_write(session, data, data_len)) {
		LIBSSH2_FREE(session, data);
		libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND, "Unable to send KEXINIT packet to remote host", 0);
		return -1;
	}

	if (session->local.kexinit) {
		LIBSSH2_FREE(session, session->local.kexinit);
	}

	session->local.kexinit = data;
	session->local.kexinit_len = data_len;

	return 0;
}
/* }}}	*/

/* {{{ libssh2_kex_agree_instr
 * Kex specific variant of strstr()
 * Needle must be preceed by BOL or ',', and followed by ',' or EOL
 */
static unsigned char *libssh2_kex_agree_instr(unsigned char *haystack, unsigned long haystack_len,
											  const unsigned char *needle, unsigned long needle_len)
{
	unsigned char *s;

	/* Haystack too short to bother trying */
	if (haystack_len < needle_len) {
		return NULL;
	}

	/* Needle at start of haystack */
	if ((strncmp(haystack, needle, needle_len) == 0) &&
		(needle_len == haystack_len || haystack[needle_len] == ',')) {
		return haystack;
	}

	s = haystack;
	/* Search until we run out of comas or we run out of haystack,
	   whichever comes first */
	while ((s = strchr(s, ',')) && ((haystack_len - (s - haystack)) > needle_len)) {
		s++;
		/* Needle at X position */
		if ((strncmp(s, needle, needle_len) == 0) &&
			(((s - haystack) + needle_len) == haystack_len || s[needle_len] == ',')) {
			return s;
		}
	}

	return NULL;
}
/* }}} */

/* {{{ libssh2_get_method_by_name
 */
static const LIBSSH2_COMMON_METHOD *libssh2_get_method_by_name(const char *name, int name_len, const LIBSSH2_COMMON_METHOD **methodlist)
{
	while (*methodlist) {
		if ((strlen((*methodlist)->name) == name_len) &&
			(strncmp((*methodlist)->name, name, name_len) == 0)) {
			return *methodlist;
		}
		methodlist++;
	}
	return NULL;
}
/* }}} */

/* {{{ libssh2_kex_agree_hostkey
 * Agree on a Hostkey which works with this kex
 */
static int libssh2_kex_agree_hostkey(LIBSSH2_SESSION *session, unsigned long kex_flags, unsigned char *hostkey, unsigned long hostkey_len)
{
	const LIBSSH2_HOSTKEY_METHOD	**hostkeyp	= libssh2_hostkey_methods();
	unsigned char *s;

	if (session->hostkey_prefs) {
		s = session->hostkey_prefs;

		while (s && *s) {
			unsigned char *p = strchr(s, ',');
			int method_len = (p ? (p - s) : strlen(s));
			if (libssh2_kex_agree_instr(hostkey, hostkey_len, s, method_len)) {
				const LIBSSH2_HOSTKEY_METHOD *method = (const LIBSSH2_HOSTKEY_METHOD*)libssh2_get_method_by_name(s, method_len, (const LIBSSH2_COMMON_METHOD**)hostkeyp);

				if (!method) {
					/* Invalid method -- Should never be reached */
					return -1;
				}

				/* So far so good, but does it suit our purposes? (Encrypting vs Signing) */
				if (((kex_flags & LIBSSH2_KEX_METHOD_FLAG_REQ_ENC_HOSTKEY) == 0) ||
					(method->encrypt)) {
					/* Either this hostkey can do encryption or this kex just doesn't require it */
					if (((kex_flags & LIBSSH2_KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY) == 0) ||
						(method->sig_verify)) {
						/* Either this hostkey can do signing or this kex just doesn't require it */
						session->hostkey = method;
						return 0;
					}
				}
			}

			s = p ? p + 1 : NULL;
		}
		return -1;
	}

	while (hostkeyp && (*hostkeyp)->name) {
		s = libssh2_kex_agree_instr(hostkey, hostkey_len,
					    (unsigned char *)(*hostkeyp)->name,
					    strlen((*hostkeyp)->name));
		if (s) {
			/* So far so good, but does it suit our purposes? (Encrypting vs Signing) */
			if (((kex_flags & LIBSSH2_KEX_METHOD_FLAG_REQ_ENC_HOSTKEY) == 0) ||
				((*hostkeyp)->encrypt)) {
				/* Either this hostkey can do encryption or this kex just doesn't require it */
				if (((kex_flags & LIBSSH2_KEX_METHOD_FLAG_REQ_SIGN_HOSTKEY) == 0) ||
					((*hostkeyp)->sig_verify)) {
					/* Either this hostkey can do signing or this kex just doesn't require it */
					session->hostkey = *hostkeyp;
					return 0;
				}
			}
		}
		hostkeyp++;
	}

	return -1;
}
/* }}} */

/* {{{ libssh2_kex_agree_kex_hostkey
 * Agree on a Key Exchange method and a hostkey encoding type
 */
static int libssh2_kex_agree_kex_hostkey(LIBSSH2_SESSION *session, unsigned char *kex, unsigned long kex_len,
																   unsigned char *hostkey, unsigned long hostkey_len)
{
	const LIBSSH2_KEX_METHOD **kexp = libssh2_kex_methods;
	unsigned char *s;

	if (session->kex_prefs) {
		s = session->kex_prefs;

		while (s && *s) {
			unsigned char *q, *p = strchr(s, ',');
			int method_len = (p ? (p - s) : strlen(s));
			if ((q = libssh2_kex_agree_instr(kex, kex_len, s, method_len))) {
				const LIBSSH2_KEX_METHOD *method = (const LIBSSH2_KEX_METHOD*)libssh2_get_method_by_name(s, method_len, (const LIBSSH2_COMMON_METHOD**)kexp);

				if (!method) {
					/* Invalid method -- Should never be reached */
					return -1;
				}

				/* We've agreed on a key exchange method,
				 * Can we agree on a hostkey that works with this kex?
				 */
				if (libssh2_kex_agree_hostkey(session, method->flags, hostkey, hostkey_len) == 0) {
					session->kex = method;
					if (session->burn_optimistic_kexinit && (kex == q)) {
						/* Server sent an optimistic packet,
						 * and client agrees with preference
						 * cancel burning the first KEX_INIT packet that comes in */
						session->burn_optimistic_kexinit = 0;
					}
					return 0;
				}
			}

			s = p ? p + 1 : NULL;
		}
		return -1;
	}

	while (*kexp && (*kexp)->name) {
		s = libssh2_kex_agree_instr(kex, kex_len,
					    (unsigned char *)(*kexp)->name,
					    strlen((*kexp)->name));
		if (s) {
			/* We've agreed on a key exchange method,
			 * Can we agree on a hostkey that works with this kex?
			 */
			if (libssh2_kex_agree_hostkey(session, (*kexp)->flags, hostkey, hostkey_len) == 0) {
				session->kex = *kexp;
				if (session->burn_optimistic_kexinit && (kex == s)) {
					/* Server sent an optimistic packet,
					 * and client agrees with preference
					 * cancel burning the first KEX_INIT packet that comes in */
					session->burn_optimistic_kexinit = 0;
				}
				return 0;
			}
		}
		kexp++;
	}
	return -1;
}
/* }}} */

/* {{{ libssh2_kex_agree_crypt
 * Agree on a cipher algo
 */
static int libssh2_kex_agree_crypt(LIBSSH2_SESSION *session,
				   libssh2_endpoint_data *endpoint,
				   unsigned char *crypt,
				   unsigned long crypt_len)
{
	const LIBSSH2_CRYPT_METHOD **cryptp = libssh2_crypt_methods();
	unsigned char *s;
	(void)session;

	if (endpoint->crypt_prefs) {
		s = endpoint->crypt_prefs;

		while (s && *s) {
			unsigned char *p = strchr(s, ',');
			int method_len = (p ? (p - s) : strlen(s));

			if (libssh2_kex_agree_instr(crypt, crypt_len, s, method_len)) {
				const LIBSSH2_CRYPT_METHOD *method =
					(const LIBSSH2_CRYPT_METHOD*)libssh2_get_method_by_name((char *)s, method_len, (const LIBSSH2_COMMON_METHOD**)cryptp);

				if (!method) {
					/* Invalid method -- Should never be reached */
					return -1;
				}

				endpoint->crypt = method;
				return 0;
			}

			s = p ? p + 1 : NULL;
		}
		return -1;
	}

	while (*cryptp && (*cryptp)->name) {
		s = libssh2_kex_agree_instr(crypt, crypt_len,
					    (unsigned char *)(*cryptp)->name,
					    strlen((*cryptp)->name));
		if (s) {
			endpoint->crypt = *cryptp;
			return 0;
		}
		cryptp++;
	}

	return -1;
}
/* }}} */

/* {{{ libssh2_kex_agree_mac
 * Agree on a message authentication hash
 */
static int libssh2_kex_agree_mac(LIBSSH2_SESSION *session, libssh2_endpoint_data *endpoint, unsigned char *mac, unsigned long mac_len)
{
	const LIBSSH2_MAC_METHOD **macp = libssh2_mac_methods();
	unsigned char *s;
	(void)session;

	if (endpoint->mac_prefs) {
		s = endpoint->mac_prefs;

		while (s && *s) {
			unsigned char *p = strchr(s, ',');
			int method_len = (p ? (p - s) : strlen(s));

			if (libssh2_kex_agree_instr(mac, mac_len, s, method_len)) {
				const LIBSSH2_MAC_METHOD *method = (const LIBSSH2_MAC_METHOD*)libssh2_get_method_by_name(s, method_len, (const LIBSSH2_COMMON_METHOD**)macp);

				if (!method) {
					/* Invalid method -- Should never be reached */
					return -1;
				}

				endpoint->mac = method;
				return 0;
			}

			s = p ? p + 1 : NULL;
		}
		return -1;
	}

	while (*macp && (*macp)->name) {
		s = libssh2_kex_agree_instr(mac, mac_len,
					    (unsigned char *)(*macp)->name,
					    strlen((*macp)->name));
		if (s) {
			endpoint->mac = *macp;
			return 0;
		}
		macp++;
	}

	return -1;
}
/* }}} */

/* {{{ libssh2_kex_agree_comp
 * Agree on a compression scheme
 */
static int libssh2_kex_agree_comp(LIBSSH2_SESSION *session, libssh2_endpoint_data *endpoint, unsigned char *comp, unsigned long comp_len)
{
	LIBSSH2_COMP_METHOD **compp = libssh2_comp_methods();
	unsigned char *s;
	(void)session;

	if (endpoint->comp_prefs) {
		s = endpoint->comp_prefs;

		while (s && *s) {
			unsigned char *p = strchr(s, ',');
			int method_len = (p ? (p - s) : strlen(s));

			if (libssh2_kex_agree_instr(comp, comp_len, s, method_len)) {
				const LIBSSH2_COMP_METHOD *method = (const LIBSSH2_COMP_METHOD*)libssh2_get_method_by_name(s, method_len, (const LIBSSH2_COMMON_METHOD**)compp);

				if (!method) {
					/* Invalid method -- Should never be reached */
					return -1;
				}

				endpoint->comp = method;
				return 0;
			}

			s = p ? p + 1 : NULL;
		}
		return -1;
	}

	while (*compp && (*compp)->name) {
		s = libssh2_kex_agree_instr(comp, comp_len,
					    (unsigned char *)(*compp)->name,
					    strlen((*compp)->name));
		if (s) {
			endpoint->comp = *compp;
			return 0;
		}
		compp++;
	}

	return -1;
}
/* }}} */

/* TODO: When in server mode we need to turn this logic on its head
 * The Client gets to make the final call on "agreed methods"
 */

/* {{{ libssh2_kex_agree_methods
 * Decide which specific method to use of the methods offered by each party
 */
static int libssh2_kex_agree_methods(LIBSSH2_SESSION *session, unsigned char *data, unsigned data_len)
{
	unsigned char *kex, *hostkey, *crypt_cs, *crypt_sc, *comp_cs, *comp_sc, *mac_cs, *mac_sc, *lang_cs, *lang_sc;
	size_t kex_len, hostkey_len, crypt_cs_len, crypt_sc_len, comp_cs_len, comp_sc_len, mac_cs_len, mac_sc_len, lang_cs_len, lang_sc_len;
	unsigned char *s = data;

	/* Skip packet_type, we know it already */
	s++;

	/* Skip cookie, don't worry, it's preserved in the kexinit field */
	s += 16;

	/* Locate each string */
	kex_len			= libssh2_ntohu32(s);		kex			= s + 4;		s += 4 + kex_len;
	hostkey_len		= libssh2_ntohu32(s);		hostkey		= s + 4;		s += 4 + hostkey_len;
	crypt_cs_len	= libssh2_ntohu32(s);		crypt_cs	= s + 4;		s += 4 + crypt_cs_len;
	crypt_sc_len	= libssh2_ntohu32(s);		crypt_sc	= s + 4;		s += 4 + crypt_sc_len;
	mac_cs_len		= libssh2_ntohu32(s);		mac_cs		= s + 4;		s += 4 + mac_cs_len;
	mac_sc_len		= libssh2_ntohu32(s);		mac_sc		= s + 4;		s += 4 + mac_sc_len;
	comp_cs_len		= libssh2_ntohu32(s);		comp_cs		= s + 4;		s += 4 + comp_cs_len;
	comp_sc_len		= libssh2_ntohu32(s);		comp_sc		= s + 4;		s += 4 + comp_sc_len;
	lang_cs_len		= libssh2_ntohu32(s);		lang_cs		= s + 4;		s += 4 + lang_cs_len;
	lang_sc_len		= libssh2_ntohu32(s);		lang_sc		= s + 4;		s += 4 + lang_sc_len;

	/* If the server sent an optimistic packet, assume that it guessed wrong.
	 * If the guess is determined to be right (by libssh2_kex_agree_kex_hostkey)
	 * This flag will be reset to zero so that it's not ignored */
	session->burn_optimistic_kexinit = *(s++);
	/* Next uint32 in packet is all zeros (reserved) */

	if (libssh2_kex_agree_kex_hostkey(session, kex, kex_len, hostkey, hostkey_len)) {
		return -1;
	}

	if (libssh2_kex_agree_crypt(session, &session->local,  crypt_cs, crypt_cs_len) ||
		libssh2_kex_agree_crypt(session, &session->remote, crypt_sc, crypt_sc_len)) {
		return -1;
	}

	if (libssh2_kex_agree_mac(session, &session->local,  mac_cs, mac_cs_len) ||
		libssh2_kex_agree_mac(session, &session->remote, mac_sc, mac_sc_len)) {
		return -1;
	}

	if (libssh2_kex_agree_comp(session, &session->local,  comp_cs, comp_cs_len) ||
		libssh2_kex_agree_comp(session, &session->remote, comp_sc, comp_sc_len)) {
		return -1;
	}

	if (libssh2_kex_agree_lang(session, &session->local,  lang_cs, lang_cs_len) ||
		libssh2_kex_agree_lang(session, &session->remote, lang_sc, lang_sc_len)) {
		return -1;
	}

	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on KEX method: %s", session->kex->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on HOSTKEY method: %s", session->hostkey->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on CRYPT_CS method: %s", session->local.crypt->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on CRYPT_SC method: %s", session->remote.crypt->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on MAC_CS method: %s", session->local.mac->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on MAC_SC method: %s", session->remote.mac->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on COMP_CS method: %s", session->local.comp->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on COMP_SC method: %s", session->remote.comp->name);
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on LANG_CS method:"); /* None yet */
	_libssh2_debug(session, LIBSSH2_DBG_KEX, "Agreed on LANG_SC method:"); /* None yet */

	/* Initialize compression layer */
	if (session->local.comp && session->local.comp->init &&
		session->local.comp->init(session, 1, &session->local.comp_abstract)) {
		return -1;
	}

	if (session->remote.comp && session->remote.comp->init &&
		session->remote.comp->init(session, 0, &session->remote.comp_abstract)) {
		return -1;
	}

	return 0;
}
/* }}} */

/* {{{ libssh2_kex_exchange
 * Exchange keys
 * Returns 0 on success, non-zero on failure
 */
int libssh2_kex_exchange(LIBSSH2_SESSION *session, int reexchange) /* session->flags |= SERVER */
{
	unsigned char *data;
	unsigned long data_len;
	int rc = 0;

	/* Prevent loop in packet_add() */
	session->state |= LIBSSH2_STATE_EXCHANGING_KEYS;

	if (reexchange) {
		session->kex = NULL;

		if (session->hostkey && session->hostkey->dtor) {
			session->hostkey->dtor(session, &session->server_hostkey_abstract);
		}
		session->hostkey = NULL;
	}

	if (!session->kex || !session->hostkey) {
		/* Preserve in case of failure */
		unsigned char *oldlocal = session->local.kexinit;
		unsigned long oldlocal_len = session->local.kexinit_len;

		session->local.kexinit = NULL;
		if (libssh2_kexinit(session)) {
			session->local.kexinit = oldlocal;
			session->local.kexinit_len = oldlocal_len;
			return -1;
		}

		if (libssh2_packet_require(session, SSH_MSG_KEXINIT, &data, &data_len)) {
			if (session->local.kexinit) {
				LIBSSH2_FREE(session, session->local.kexinit);
			}
			session->local.kexinit = oldlocal;
			session->local.kexinit_len = oldlocal_len;
			return -2;
		}

		if (session->remote.kexinit) {
			LIBSSH2_FREE(session, session->remote.kexinit);
		}
		session->remote.kexinit = data;
		session->remote.kexinit_len = data_len;

		if (libssh2_kex_agree_methods(session, data, data_len)) {
			rc = -3;
		}
	}

	if (rc == 0) {
		if (session->kex->exchange_keys(session)) {
			libssh2_error(session, LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE, "Unrecoverable error exchanging keys", 0);
			rc = -4;
		}
	}

	/* Done with kexinit buffers */
	if (session->local.kexinit) {
		LIBSSH2_FREE(session, session->local.kexinit);
		session->local.kexinit = NULL;
	}
	if (session->remote.kexinit) {
		LIBSSH2_FREE(session, session->remote.kexinit);
		session->remote.kexinit = NULL;
	}

	session->state &= ~LIBSSH2_STATE_EXCHANGING_KEYS;

	return rc;
}
/* }}} */

/* {{{ libssh2_session_method_pref
 * Set preferred method
 */
LIBSSH2_API int libssh2_session_method_pref(LIBSSH2_SESSION *session, int method_type, const char *prefs)
{
	char **prefvar, *s, *newprefs;
	int prefs_len = strlen(prefs);
	const LIBSSH2_COMMON_METHOD **mlist;

	switch (method_type) {
		case LIBSSH2_METHOD_KEX:
			prefvar = &session->kex_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_kex_methods;
			break;
		case LIBSSH2_METHOD_HOSTKEY:
			prefvar = &session->hostkey_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_hostkey_methods();
			break;
		case LIBSSH2_METHOD_CRYPT_CS:
			prefvar = &session->local.crypt_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_crypt_methods();
			break;
		case LIBSSH2_METHOD_CRYPT_SC:
			prefvar = &session->remote.crypt_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_crypt_methods();
			break;
		case LIBSSH2_METHOD_MAC_CS:
			prefvar = &session->local.mac_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_mac_methods();
			break;
		case LIBSSH2_METHOD_MAC_SC:
			prefvar = &session->remote.mac_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_mac_methods();
			break;
		case LIBSSH2_METHOD_COMP_CS:
			prefvar = &session->local.comp_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_comp_methods();
			break;
		case LIBSSH2_METHOD_COMP_SC:
			prefvar = &session->remote.comp_prefs;
			mlist = (const LIBSSH2_COMMON_METHOD**)libssh2_comp_methods();
			break;
		case LIBSSH2_METHOD_LANG_CS:
			prefvar = &session->local.lang_prefs;
			mlist = NULL;
			break;
		case LIBSSH2_METHOD_LANG_SC:
			prefvar = &session->remote.lang_prefs;
			mlist = NULL;
			break;
		default:
			libssh2_error(session, LIBSSH2_ERROR_INVAL, "Invalid parameter specified for method_type", 0);
			return -1;
	}

	s = newprefs = LIBSSH2_ALLOC(session, prefs_len + 1);
	if (!newprefs) {
		libssh2_error(session, LIBSSH2_ERROR_ALLOC, "Error allocated space for method preferences", 0);
		return -1;
	}
	memcpy(s, prefs, prefs_len + 1);

	while (s && *s) {
		char *p = strchr(s, ',');
		int method_len = p ? (p - s) : (int) strlen(s);

		if (!libssh2_get_method_by_name(s, method_len, mlist)) {
			/* Strip out unsupported method */
			if (p) {
				memcpy(s, p + 1, strlen(s) - method_len);
			} else {
				if (s > newprefs) {
					*(--s) = '\0';
				} else {
					*s = '\0';
				}
			}
		}

		s = p ? (p + 1) : NULL;
	}

	if (strlen(newprefs) == 0) {
		libssh2_error(session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED, "The requested method(s) are not currently supported", 0);
		LIBSSH2_FREE(session, newprefs);
		return -1;
	}

	if (*prefvar) {
		LIBSSH2_FREE(session, *prefvar);
	}
	*prefvar = newprefs;

	return 0;
}
/* }}} */
