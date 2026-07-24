/*
 * Copyright (C) Daniel Stenberg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "libssh2_priv.h"

struct known_host {
    struct list_node node;
    char *name;          /* points to the name or the hash (allocated) */
    size_t name_len;     /* needed for hashed data */
    int port;            /* if non-zero, a specific port this key is for on
                            this host */
    int typemask;        /* plain, SHA1, custom, ... */
    char *salt;          /* points to binary salt (allocated) */
    size_t salt_len;     /* size of salt */
    char *key;           /* the (allocated) associated key. This is kept base64
                            encoded in memory. */
    char *key_type_name; /* the (allocated) key type name */
    size_t key_type_len; /* size of key_type_name */
    char *comment;       /* the (allocated) optional comment text, may be
                            NULL */
    size_t comment_len;  /* the size of comment */

    /* this is the struct we expose externally */
    struct libssh2_knownhost external;
};

struct _LIBSSH2_KNOWNHOSTS {
    LIBSSH2_SESSION *session;  /* the session this "belongs to" */
    struct list_head head;
};

static void knownhost_entry_free(LIBSSH2_SESSION *session,
                                 struct known_host *entry)
{
    if(entry) {
        if(entry->comment)
            SSH2_FREE(session, entry->comment);
        if(entry->key_type_name)
            SSH2_FREE(session, entry->key_type_name);
        if(entry->key)
            SSH2_FREE(session, entry->key);
        if(entry->salt)
            SSH2_FREE(session, entry->salt);
        if(entry->name)
            SSH2_FREE(session, entry->name);
        SSH2_FREE(session, entry);
    }
}

/*
 * Init a collection of known hosts. Returns the pointer to a collection.
 */
LIBSSH2_KNOWNHOSTS *libssh2_knownhost_init(LIBSSH2_SESSION *session)
{
    LIBSSH2_KNOWNHOSTS *knh;

    if(!session)
        return NULL;

    knh = SSH2_ALLOC(session, sizeof(struct _LIBSSH2_KNOWNHOSTS));
    if(!knh) {
        ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                 "Unable to allocate memory for known-hosts collection");
        return NULL;
    }

    knh->session = session;

    ssh2_list_init(&knh->head);

    return knh;
}

#define KNOWNHOST_MAGIC 0xdeadcafe
/*
 * Copies data from the internal to the external representation struct.
 */
static struct libssh2_knownhost *knownhost_to_external(struct known_host *node)
{
    struct libssh2_knownhost *ext = &node->external;

    ext->magic = KNOWNHOST_MAGIC;
    ext->node = node;
    ext->name = ((node->typemask & LIBSSH2_KNOWNHOST_TYPE_MASK) ==
                 LIBSSH2_KNOWNHOST_TYPE_PLAIN) ? node->name : NULL;
    ext->key = node->key;
    ext->typemask = node->typemask;

    return ext;
}

#define KNOWNHOST_MAX_LEN  (1024 * 1024)

static int knownhost_add(LIBSSH2_KNOWNHOSTS *hosts,
                         const char *host, const char *salt,
                         const char *key_type_name, size_t key_type_len,
                         const char *key, size_t keylen,
                         const char *comment, size_t commentlen,
                         int typemask, struct libssh2_knownhost **store)
{
    struct known_host *entry;
    size_t hostlen;
    int rc;
    char *ptr = NULL;
    size_t ptrlen = 0;

    if(!hosts || !host || !key)
        return LIBSSH2_ERROR_BAD_USE;

    /* keylen == 0 fell back to strlen(key) until libssh2 1.11.1.
       Require explicit length now. */
    if(!keylen)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_BAD_USE,
                        "Known-host key length required");

    hostlen = strlen(host);

    if(hostlen > KNOWNHOST_MAX_LEN ||
       keylen > KNOWNHOST_MAX_LEN)
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;

    /* make sure we have a key type set */
    if(!(typemask & LIBSSH2_KNOWNHOST_KEY_MASK))
        return ssh2_err(hosts->session, LIBSSH2_ERROR_INVAL,
                        "No key type set");

    entry = SSH2_CALLOC(hosts->session, sizeof(*entry));
    if(!entry)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                        "Unable to allocate memory for known host entry");

    entry->typemask = typemask;

    switch(entry->typemask & LIBSSH2_KNOWNHOST_TYPE_MASK) {
    case LIBSSH2_KNOWNHOST_TYPE_PLAIN:
    case LIBSSH2_KNOWNHOST_TYPE_CUSTOM:
        entry->name = SSH2_ALLOC(hosts->session, hostlen + 1);
        if(!entry->name) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for hostname");
            goto error;
        }
        memcpy(entry->name, host, hostlen + 1);
        entry->name_len = hostlen;
        break;
    case LIBSSH2_KNOWNHOST_TYPE_SHA1: {
        size_t salt_len;

        rc = ssh2_base64_decode(hosts->session, &ptr, &ptrlen, host, hostlen);
        if(rc)
            goto error;

        if(!ptrlen) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_INVAL,
                          "Base64 decoded value is invalid");
            goto error;
        }

        if(!salt) {
            if(ptr)
                SSH2_FREE(hosts->session, ptr);
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_INVAL, "Salt is NULL");
            goto error;
        }

        salt_len = strlen(salt);
        if(salt_len > KNOWNHOST_MAX_LEN) {
            if(ptr)
                SSH2_FREE(hosts->session, ptr);
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                          "Salt too long");
            goto error;
        }

        entry->name = ptr;
        entry->name_len = ptrlen;

        rc = ssh2_base64_decode(hosts->session, &ptr, &ptrlen, salt, salt_len);
        if(rc)
            goto error;

        if(!ptrlen) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_INVAL,
                          "Base64 decoded value is invalid");
            goto error;
        }

        entry->salt = ptr;
        entry->salt_len = ptrlen;
        break;
    }
    default:
        rc = ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                      "Unrecognized hostname type");
        goto error;
    }

    if(typemask & LIBSSH2_KNOWNHOST_KEYENC_BASE64) {
        /* the provided key is base64 encoded already */
        entry->key = SSH2_ALLOC(hosts->session, keylen + 1);
        if(!entry->key) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for key");
            goto error;
        }
        memcpy(entry->key, key, keylen);
        entry->key[keylen] = '\0';
    }
    else {
        /* key is raw, we base64 encode it and store it as such */
        size_t nlen = ssh2_base64_encode(hosts->session, key, keylen, &ptr);
        if(!nlen) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for base64-encoded key");
            goto error;
        }

        entry->key = ptr;
    }

    if(key_type_name && (typemask & LIBSSH2_KNOWNHOST_KEY_MASK) ==
                        LIBSSH2_KNOWNHOST_KEY_UNKNOWN) {
        if(key_type_len > KNOWNHOST_MAX_LEN) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                          "Key type too long");
            goto error;
        }
        entry->key_type_name = SSH2_ALLOC(hosts->session, key_type_len + 1);
        if(!entry->key_type_name) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for key type");
            goto error;
        }
        memcpy(entry->key_type_name, key_type_name, key_type_len);
        entry->key_type_name[key_type_len] = '\0';
        entry->key_type_len = key_type_len;
    }

    if(comment) {
        if(commentlen > KNOWNHOST_MAX_LEN) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                          "Comment too long");
            goto error;
        }
        entry->comment = SSH2_ALLOC(hosts->session, commentlen + 1);
        if(!entry->comment) {
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for comment");
            goto error;
        }
        memcpy(entry->comment, comment, commentlen);
        entry->comment[commentlen] = '\0';
        entry->comment_len = commentlen;
    }
    else
        entry->comment = NULL;

    /* add this new host to the big list of known hosts */
    ssh2_list_add(&hosts->head, &entry->node);

    if(store)
        *store = knownhost_to_external(entry);

    return LIBSSH2_ERROR_NONE;
error:
    knownhost_entry_free(hosts->session, entry);
    return rc;
}

#ifndef LIBSSH2_NO_DEPRECATED
/*
 * DEPRECATED, DO NOT USE!
 *
 * Add a host and its associated key to the collection of known hosts.
 *
 * The 'type' argument specifies on what format the given host and keys are:
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - SHA1(<salt> <host>) base64-encoded!
 * custom - another hash
 *
 * If 'sha1' is selected as type, the salt must be provided to the salt
 * argument. This too base64 encoded.
 *
 * The SHA-1 hash is what OpenSSH can be told to use in known_hosts files.  If
 * a custom type is used, salt is ignored and you must provide the host
 * pre-hashed when checking for it in the libssh2_knownhost_check() function.
 */
int libssh2_knownhost_add(LIBSSH2_KNOWNHOSTS *hosts,
                          const char *host, const char *salt,
                          const char *key, size_t keylen,
                          int typemask, struct libssh2_knownhost **store)
{
    return knownhost_add(hosts, host, salt, NULL, 0, key, keylen, NULL,
                         0, typemask, store);
}
#endif

/*
 * Add a host and its associated key to the collection of known hosts.
 *
 * Takes a comment argument that may be NULL.  A NULL comment indicates
 * there is no comment and the entry ends directly after the key
 * when written out to a file.  An empty string "" comment indicates an
 * empty comment which causes a single space to be written after the key.
 *
 * The 'type' argument specifies on what format the given host and keys are:
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - SHA1(<salt> <host>) base64-encoded!
 * custom - another hash
 *
 * If 'sha1' is selected as type, the salt must be provided to the salt
 * argument. This too base64 encoded.
 *
 * The SHA-1 hash is what OpenSSH can be told to use in known_hosts files.  If
 * a custom type is used, salt is ignored and you must provide the host
 * pre-hashed when checking for it in the libssh2_knownhost_check() function.
 */
int libssh2_knownhost_addc(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *host, const char *salt,
                           const char *key, size_t keylen,
                           const char *comment, size_t commentlen,
                           int typemask, struct libssh2_knownhost **store)
{
    return knownhost_add(hosts, host, salt, NULL, 0, key, keylen,
                         comment, commentlen, typemask, store);
}

/*
 * Check a host and its associated key against the collection of known hosts.
 *
 * The typemask is the type/format of the given hostname and key
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - NOT SUPPORTED AS INPUT
 * custom - prehashed base64 encoded. Note that this cannot use any salts.
 *
 * Returns:
 *
 * LIBSSH2_KNOWNHOST_CHECK_FAILURE
 * LIBSSH2_KNOWNHOST_CHECK_NOTFOUND
 * LIBSSH2_KNOWNHOST_CHECK_MATCH
 * LIBSSH2_KNOWNHOST_CHECK_MISMATCH
 */
static int knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *hostp, int port,
                           const char *key, size_t keylen,
                           int typemask,
                           struct libssh2_knownhost **store)
{
    struct known_host *node;
    struct known_host *badkey = NULL;
    int type = typemask & LIBSSH2_KNOWNHOST_TYPE_MASK;
    char *keyalloc = NULL;
    int rc = LIBSSH2_KNOWNHOST_CHECK_NOTFOUND;
    char hostbuff[270]; /* most hostnames cannot be longer than like 256 */
    const char *host;
    int numcheck; /* number of host combos to check */
    int match = 0;

    if(!hosts)
        return LIBSSH2_KNOWNHOST_CHECK_FAILURE;

    if(!hostp || !key) {
        ssh2_err(hosts->session, LIBSSH2_ERROR_BAD_USE,
                 "Known-host hostname and key required");
        return LIBSSH2_KNOWNHOST_CHECK_FAILURE;
    }

    if(keylen > KNOWNHOST_MAX_LEN) {
        ssh2_err(hosts->session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                 "Known-host key too long");
        return LIBSSH2_KNOWNHOST_CHECK_FAILURE;
    }

    if(type == LIBSSH2_KNOWNHOST_TYPE_SHA1)
        /* we cannot work with a SHA1 as given input */
        return LIBSSH2_KNOWNHOST_CHECK_MISMATCH;

    /* if a port number is given, check for a '[host]:port' first before the
       plain 'host' */
    if(port >= 0) {
        int len = ssh2_snprintf(hostbuff, sizeof(hostbuff), "[%s]:%d",
                                hostp, port);
        if(len < 0 || len >= (int)sizeof(hostbuff)) {
            ssh2_err(hosts->session, LIBSSH2_ERROR_BUFFER_TOO_SMALL,
                     "Known-host write buffer too small");
            return LIBSSH2_KNOWNHOST_CHECK_FAILURE;
        }
        host = hostbuff;
        numcheck = 2; /* check both combos, start with this */
    }
    else {
        host = hostp;
        numcheck = 1; /* only check this host version */
    }

    if(!(typemask & LIBSSH2_KNOWNHOST_KEYENC_BASE64)) {
        /* we got a raw key input, convert it to base64 for the checks below */
        size_t nlen = ssh2_base64_encode(hosts->session, key, keylen,
                                         &keyalloc);
        if(!nlen) {
            ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for base64-encoded key");
            return LIBSSH2_KNOWNHOST_CHECK_FAILURE;
        }

        /* make the key point to this */
        key = keyalloc;
    }

    do {
        node = ssh2_list_first(&hosts->head);
        while(node) {
            switch(node->typemask & LIBSSH2_KNOWNHOST_TYPE_MASK) {
            case LIBSSH2_KNOWNHOST_TYPE_PLAIN:
                if(type == LIBSSH2_KNOWNHOST_TYPE_PLAIN)
                    match = !strcmp(host, node->name);
                break;
            case LIBSSH2_KNOWNHOST_TYPE_CUSTOM:
                if(type == LIBSSH2_KNOWNHOST_TYPE_CUSTOM)
                    match = !strcmp(host, node->name);
                break;
            case LIBSSH2_KNOWNHOST_TYPE_SHA1:
                if(type == LIBSSH2_KNOWNHOST_TYPE_PLAIN) {
                    /* when we have the SHA1 version stored, we can use a
                       plain input to produce a hash to compare with the
                       stored hash. */
                    unsigned char hash[SSH2_SHA1_DIG_LEN];
                    ssh2_hmac_ctx ctx;

                    if(node->name_len != sizeof(hash))
                        /* the name hash length must be the SHA1 size or
                           we cannot match it */
                        break;
                    if(!ssh2_hmac_ctx_init(&ctx))
                        break;
                    if(!ssh2_hmac_init(&ctx, SSH2_SHA1_HMAC,
                                       node->salt, node->salt_len) ||
                       !ssh2_hmac_update(&ctx, host, strlen(host)) ||
                       !ssh2_hmac_final(&ctx, hash, sizeof(hash))) {
                        ssh2_hmac_cleanup(&ctx);
                        break;
                    }
                    ssh2_hmac_cleanup(&ctx);

                    if(!memcmp(hash, node->name, sizeof(hash)))
                        /* this is a node we are interested in */
                        match = 1;
                }
                break;
            default: /* unsupported type */
                break;
            }
            if(match) {
                int host_key_type = typemask & LIBSSH2_KNOWNHOST_KEY_MASK;
                int known_key_type =
                    node->typemask & LIBSSH2_KNOWNHOST_KEY_MASK;
                /* match on key type as follows:
                   - never match on an unknown key type
                   - if key_type is set to zero, ignore it an match always
                   - otherwise match when both key types are equal */
                if(host_key_type != LIBSSH2_KNOWNHOST_KEY_UNKNOWN &&
                   (host_key_type == 0 ||
                    host_key_type == known_key_type)) {
                    /* hostname and key type match, now compare the keys */
                    if(!strcmp(key, node->key)) {
                        /* they match! */
                        if(store)
                            *store = knownhost_to_external(node);
                        badkey = NULL;
                        rc = LIBSSH2_KNOWNHOST_CHECK_MATCH;
                        break;
                    }
                    else {
                        /* remember the first node that had a host match but a
                           failed key match since we continue our search from
                           here */
                        if(!badkey)
                            badkey = node;
                    }
                }
                match = 0; /* do not count this as a match anymore */
            }
            node = ssh2_list_next(&node->node);
        }
        host = hostp;
    } while(!match && --numcheck);

    if(badkey) {
        /* key mismatch */
        if(store)
            *store = knownhost_to_external(badkey);
        rc = LIBSSH2_KNOWNHOST_CHECK_MISMATCH;
    }

    if(keyalloc)
        SSH2_FREE(hosts->session, keyalloc);

    return rc;
}

/*
 * Check a host and its associated key against the collection of known hosts.
 *
 * The typemask is the type/format of the given hostname and key
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - NOT SUPPORTED AS INPUT
 * custom - prehashed base64 encoded. Note that this cannot use any salts.
 *
 * Returns:
 *
 * LIBSSH2_KNOWNHOST_CHECK_FAILURE
 * LIBSSH2_KNOWNHOST_CHECK_NOTFOUND
 * LIBSSH2_KNOWNHOST_CHECK_MATCH
 * LIBSSH2_KNOWNHOST_CHECK_MISMATCH
 */
int libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,
                            const char *host, const char *key, size_t keylen,
                            int typemask,
                            struct libssh2_knownhost **store)
{
    return knownhost_check(hosts, host, -1, key, keylen, typemask, store);
}

/*
 * Check a host+port and its associated key against the collection of known
 * hosts.
 *
 * Note that if 'port' is specified as greater than zero, the check function
 * is able to check for a dedicated key for this particular host+port
 * combo, and if 'port' is negative it only checks for the generic host key.
 *
 * The typemask is the type/format of the given hostname and key
 *
 * plain  - ascii "hostname.domain.tld"
 * sha1   - NOT SUPPORTED AS INPUT
 * custom - prehashed base64 encoded. Note that this cannot use any salts.
 *
 * Returns:
 *
 * LIBSSH2_KNOWNHOST_CHECK_FAILURE
 * LIBSSH2_KNOWNHOST_CHECK_NOTFOUND
 * LIBSSH2_KNOWNHOST_CHECK_MATCH
 * LIBSSH2_KNOWNHOST_CHECK_MISMATCH
 */
int libssh2_knownhost_checkp(LIBSSH2_KNOWNHOSTS *hosts,
                             const char *host, int port,
                             const char *key, size_t keylen,
                             int typemask,
                             struct libssh2_knownhost **store)
{
    return knownhost_check(hosts, host, port, key, keylen, typemask, store);
}

/*
 * Remove a host from the collection of known hosts.
 */
int libssh2_knownhost_del(LIBSSH2_KNOWNHOSTS *hosts,
                          struct libssh2_knownhost *entry)
{
    struct known_host *node;

    if(!hosts)
        return LIBSSH2_ERROR_BAD_USE;

    /* check that this was retrieved the right way or get out */
    if(!entry || entry->magic != KNOWNHOST_MAGIC)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_INVAL,
                        "Invalid host information");

    /* get the internal node pointer */
    node = entry->node;

    /* unlink from the list of all hosts */
    ssh2_list_remove(&node->node);

    /* clear the struct now since the memory in which it is allocated is
       about to be freed! */
    memset(entry, 0, sizeof(*entry));

    /* free all resources */
    knownhost_entry_free(hosts->session, node);

    return LIBSSH2_ERROR_NONE;
}

/*
 * Free an entire collection of known hosts.
 */
void libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS *hosts)
{
    struct known_host *node;
    struct known_host *next;

    if(!hosts)
        return;

    for(node = ssh2_list_first(&hosts->head); node; node = next) {
        next = ssh2_list_next(&node->node);
        knownhost_entry_free(hosts->session, node);
    }
    SSH2_FREE(hosts->session, hosts);
}

/* old style plain text: [name]([,][name])*
 *
 * for the sake of simplicity, we add them as separate hosts with the same
 * key
 */
static int knownhost_line_legacy(LIBSSH2_KNOWNHOSTS *hosts,
                                 const char *host, size_t hostlen,
                                 const char *key_type_name,
                                 size_t key_type_len,
                                 const char *key, size_t keylen,
                                 int key_type,
                                 const char *comment, size_t commentlen)
{
    int rc = 0;
    size_t namelen = 0;
    const char *name = host + hostlen;

    if(hostlen < 1)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Failed to parse known_hosts line (no hostnames)");

    while(name > host) {
        --name;
        ++namelen;

        /* when we get to the start or see a comma coming up, add the host
           name to the collection */
        if(name == host || *(name - 1) == ',') {

            char hostbuf[256];

            /* make sure we do not overflow the buffer */
            if(namelen >= sizeof(hostbuf) - 1)
                return ssh2_err(hosts->session,
                                LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                                "Failed to parse known_hosts line "
                                "(unexpected length)");

            /* copy hostname to the temp buffer and null-terminate */
            memcpy(hostbuf, name, namelen);
            hostbuf[namelen] = '\0';

            rc = knownhost_add(hosts, hostbuf, NULL,
                               key_type_name, key_type_len,
                               key, keylen,
                               comment, commentlen,
                               key_type | LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                               LIBSSH2_KNOWNHOST_KEYENC_BASE64, NULL);
            if(rc)
                return rc;

            if(name > host) {
                namelen = 0;
                --name; /* skip comma */
            }
        }
    }

    return rc;
}

/* |1|[salt]|[hash] */
static int knownhost_line_hashed(LIBSSH2_KNOWNHOSTS *hosts,
                                 const char *host, size_t hostlen,
                                 const char *key_type_name,
                                 size_t key_type_len,
                                 const char *key, size_t keylen,
                                 int key_type,
                                 const char *comment, size_t commentlen)
{
    const char *p;
    char saltbuf[32];
    char hostbuf[256];

    const char *salt = &host[3]; /* skip the magic marker */
    hostlen -= 3; /* deduct the marker */

    /* this is where the salt starts, find the end of it */
    for(p = salt; (size_t)(p - salt) < hostlen && *p && *p != '|'; p++)
        ;

    if((size_t)(p - salt) < hostlen && *p == '|') {
        const char *hash = NULL;
        size_t saltlen = p - salt;
        if(saltlen >= (sizeof(saltbuf) - 1)) /* weird length */
            return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                            "Failed to parse known_hosts line "
                            "(unexpectedly long salt)");

        memcpy(saltbuf, salt, saltlen);
        saltbuf[saltlen] = '\0';
        salt = saltbuf; /* point to the stack based buffer */

        hash = p + 1; /* the host hash is after the separator */

        /* now make the host point to the hash */
        host = hash;
        hostlen -= saltlen + 1; /* deduct the salt and separator */

        /* check that the lengths seem sensible */
        if(hostlen >= sizeof(hostbuf) - 1)
            return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                            "Failed to parse known_hosts line "
                            "(unexpected length)");

        memcpy(hostbuf, host, hostlen);
        hostbuf[hostlen] = '\0';

        return knownhost_add(hosts, hostbuf, salt,
                             key_type_name, key_type_len,
                             key, keylen,
                             comment, commentlen,
                             key_type | LIBSSH2_KNOWNHOST_TYPE_SHA1 |
                             LIBSSH2_KNOWNHOST_KEYENC_BASE64, NULL);
    }
    else
        return 0; /* XXX: This should be an error, should it not? */
}

/*
 * Parse a single known_host line pre-split into host and key.
 *
 * The key part may include an optional comment which is parsed here
 * for ssh-rsa and ssh-dsa keys.  Comments in other key types are not handled.
 *
 * The function assumes new-lines have already been removed from the arguments.
 */
static int knownhost_line(LIBSSH2_KNOWNHOSTS *hosts,
                          const char *host, size_t hostlen,
                          const char *key, size_t keylen)
{
    const char *comment = NULL;
    const char *key_type_name = NULL;
    size_t commentlen = 0;
    size_t key_type_len = 0;
    int key_type;

    /* make some checks that the lengths seem sensible */
    if(keylen < 20)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Failed to parse known_hosts line (key too short)");

    switch(key[0]) {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        key_type = LIBSSH2_KNOWNHOST_KEY_RSA1;

        /* Note that the old-style keys (RSA1) are not truly base64, but we
         * claim it is for now since we can get away with strcmp()ing the
         * entire anything anyway! We need to check and fix these to make them
         * work properly.
         */
        break;

    default:
        key_type_name = key;
        while(keylen && *key && *key != ' ' && *key != '\t') {
            key++;
            keylen--;
        }
        key_type_len = key - key_type_name;

        if(!strncmp(key_type_name, "ssh-ed25519", key_type_len))
            key_type = LIBSSH2_KNOWNHOST_KEY_ED25519;
        else if(!strncmp(key_type_name, "ecdsa-sha2-nistp256", key_type_len))
            key_type = LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
        else if(!strncmp(key_type_name, "ecdsa-sha2-nistp384", key_type_len))
            key_type = LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
        else if(!strncmp(key_type_name, "ecdsa-sha2-nistp521", key_type_len))
            key_type = LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
        else if(!strncmp(key_type_name, "ssh-rsa", key_type_len))
            key_type = LIBSSH2_KNOWNHOST_KEY_SSHRSA;
#if LIBSSH2_DSA && !defined(LIBSSH2_NO_DEPRECATED)
        else if(!strncmp(key_type_name, "ssh-dss", key_type_len))
            key_type = LIBSSH2_KNOWNHOST_KEY_SSHDSS;
#endif
        else
            key_type = LIBSSH2_KNOWNHOST_KEY_UNKNOWN;

        /* skip whitespaces */
        while(keylen && (*key == ' ' || *key == '\t')) {
            key++;
            keylen--;
        }

        comment = key;
        commentlen = keylen;

        /* move over key */
        while(commentlen && *comment &&
              *comment != ' ' && *comment != '\t') {
            comment++;
            commentlen--;
        }

        /* reduce key by comment length */
        keylen -= commentlen;

        /* Distinguish empty comment (a space) from no comment (no space) */
        if(commentlen == 0)
            comment = NULL;

        /* skip whitespaces */
        while(commentlen && *comment &&
              (*comment == ' ' || *comment == '\t')) {
            comment++;
            commentlen--;
        }
        break;
    }

    if(!keylen)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Failed to parse known_hosts line (no key)");

    /* Figure out host format */
    if(hostlen < 3 || memcmp(host, "|1|", 3))
        /* old style plain text: [name]([,][name])*
           for simplicity, we add them as separate hosts with the same key */
        return knownhost_line_legacy(hosts, host, hostlen, key_type_name,
                                     key_type_len, key, keylen, key_type,
                                     comment, commentlen);
    else
        /* |1|[salt]|[hash] */
        return knownhost_line_hashed(hosts, host, hostlen, key_type_name,
                                     key_type_len, key, keylen, key_type,
                                     comment, commentlen);
}

/*
 * Pass in a line of a file of 'type'.
 *
 * LIBSSH2_KNOWNHOST_FILE_OPENSSH is the only supported type.
 *
 * OpenSSH line format:
 *
 * <host> <key>
 *
 * Where the two parts can be created like:
 *
 * <host> can be either
 * <name> or <hash>
 *
 * <name> consists of
 * [name] optionally followed by [,name] one or more times
 *
 * <hash> consists of
 * |1|<salt>|hash
 *
 * <key> can be one of:
 * [RSA bits] [e] [n as a decimal number]
 * 'ssh-dss' [base64-encoded-key]
 * 'ssh-rsa' [base64-encoded-key]
 *
 */
int libssh2_knownhost_readline(LIBSSH2_KNOWNHOSTS *hosts,
                               const char *line, size_t len, int type)
{
    const char *cp;
    const char *hostp;
    const char *keyp;
    size_t hostlen;
    size_t keylen;
    int rc;

    if(!hosts || !line)
        return LIBSSH2_ERROR_BAD_USE;

    if(len > KNOWNHOST_MAX_LEN)
        return LIBSSH2_ERROR_OUT_OF_BOUNDARY;

    if(type != LIBSSH2_KNOWNHOST_FILE_OPENSSH)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Unsupported type of known-host information store");

    cp = line;

    /* skip leading whitespaces */
    while(len && (*cp == ' ' || *cp == '\t')) {
        cp++;
        len--;
    }

    if(!len || !*cp || *cp == '#' || *cp == '\n')
        return LIBSSH2_ERROR_NONE; /* comment or empty line */

    hostp = cp; /* the host part starts here */

    /* move over the host to the separator */
    while(len && *cp && *cp != ' ' && *cp != '\t') {
        cp++;
        len--;
    }

    hostlen = cp - hostp;

    /* the key starts after the whitespaces */
    while(len && *cp && (*cp == ' ' || *cp == '\t')) {
        cp++;
        len--;
    }

    if(!len || !*cp) /* illegal line */
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Failed to parse known_hosts line");

    keyp = cp; /* the key starts here */

    /* check if the line (key) ends with a newline and if so kill it */
    while(len && *cp && *cp != '\n') {
        cp++;
        len--;
    }

    /* key length is the parsed span, naturally excluding newline */
    keylen = cp - keyp;

    /* deal with this one host+key line */
    rc = knownhost_line(hosts, hostp, hostlen, keyp, keylen);
    if(rc)
        return rc; /* failed */

    return LIBSSH2_ERROR_NONE; /* success */
}

/*
 * Read hosts+key pairs from a given file.
 *
 * Returns a negative value for error or number of successfully added hosts.
 */
int libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS *hosts,
                               const char *filename, int type)
{
    FILE *fp;
    int num = 0;
    char buf[4092];

    if(!hosts || !filename)
        return LIBSSH2_ERROR_BAD_USE;

    if(type != LIBSSH2_KNOWNHOST_FILE_OPENSSH)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Unsupported type of known-host information store");

    fp = ssh2_fopen(filename, FOPEN_READTEXT);
    if(fp) {
        while(fgets(buf, sizeof(buf), fp)) {
            if(libssh2_knownhost_readline(hosts, buf, strlen(buf), type)) {
                num = ssh2_err(hosts->session, LIBSSH2_ERROR_KNOWN_HOSTS,
                               "Failed to parse known hosts file");
                break;
            }
            num++;
        }
        fclose(fp);
    }
    else
        return ssh2_err(hosts->session, LIBSSH2_ERROR_FILE,
                        "Failed to open file");

    return num;
}

/*
 * Ask libssh2 to convert a known host to an output line for storage.
 *
 * Note that this function returns LIBSSH2_ERROR_BUFFER_TOO_SMALL if the given
 * output buffer is too small to hold the desired output. The 'outlen' field
 * then contains the size libssh2 wanted to store, which then is the
 * smallest sufficient buffer it would require.
 */
static int knownhost_writeline(LIBSSH2_KNOWNHOSTS *hosts,
                               struct known_host *node,
                               char *buf, size_t buflen,
                               size_t *outlen, int type)
{
    size_t required_size;

    const char *key_type_name;
    size_t key_type_len;

    /* we only support this single file type for now, bail out on all other
       attempts */
    if(type != LIBSSH2_KNOWNHOST_FILE_OPENSSH)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Unsupported type of known-host information store");

    switch(node->typemask & LIBSSH2_KNOWNHOST_KEY_MASK) {
    case LIBSSH2_KNOWNHOST_KEY_RSA1:
        key_type_name = NULL;
        key_type_len = 0;
        break;
    case LIBSSH2_KNOWNHOST_KEY_SSHRSA:
        key_type_name = "ssh-rsa";
        key_type_len = 7;
        break;
#if LIBSSH2_DSA && !defined(LIBSSH2_NO_DEPRECATED)
    case LIBSSH2_KNOWNHOST_KEY_SSHDSS:
        key_type_name = "ssh-dss";
        key_type_len = 7;
        break;
#endif
    case LIBSSH2_KNOWNHOST_KEY_ECDSA_256:
        key_type_name = "ecdsa-sha2-nistp256";
        key_type_len = 19;
        break;
    case LIBSSH2_KNOWNHOST_KEY_ECDSA_384:
        key_type_name = "ecdsa-sha2-nistp384";
        key_type_len = 19;
        break;
    case LIBSSH2_KNOWNHOST_KEY_ECDSA_521:
        key_type_name = "ecdsa-sha2-nistp521";
        key_type_len = 19;
        break;
    case LIBSSH2_KNOWNHOST_KEY_ED25519:
        key_type_name = "ssh-ed25519";
        key_type_len = 11;
        break;
    case LIBSSH2_KNOWNHOST_KEY_UNKNOWN:
        key_type_name = node->key_type_name;
        if(key_type_name) {
            key_type_len = node->key_type_len;
            break;
        }
        /* otherwise fallback to default and error */
        SSH2_FALLTHROUGH();
    default:
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Unsupported type of known-host entry");
    }

    /* When putting together the host line there are three aspects to consider:
       - Hashed (SHA1) or unhashed hostname
       - key name or no key name (RSA1)
       - comment or no comment

       This means there are 2^3 different formats:
       ("|1|%s|%s %s %s %s\n", salt, hashed_host, key_name, key, comment)
       ("|1|%s|%s %s %s\n", salt, hashed_host, key_name, key)
       ("|1|%s|%s %s %s\n", salt, hashed_host, key, comment)
       ("|1|%s|%s %s\n", salt, hashed_host, key)
       ("%s %s %s %s\n", host, key_name, key, comment)
       ("%s %s %s\n", host, key_name, key)
       ("%s %s %s\n", host, key, comment)
       ("%s %s\n", host, key)

       Even if the buffer is too small, we have to set outlen to the number of
       characters the complete line would have taken. We also do not write
       anything to the buffer unless we are sure we can write everything to the
       buffer. */

    required_size = strlen(node->key);

    if(key_type_len)
        required_size += key_type_len + 1; /* ' ' = 1 */
    if(node->comment)
        required_size += node->comment_len + 1; /* ' ' = 1 */

    if((node->typemask & LIBSSH2_KNOWNHOST_TYPE_MASK) ==
       LIBSSH2_KNOWNHOST_TYPE_SHA1) {
        char *namealloc;
        size_t name_base64_len;
        char *saltalloc;
        size_t salt_base64_len;

        name_base64_len = ssh2_base64_encode(hosts->session, node->name,
                                             node->name_len, &namealloc);
        if(!name_base64_len)
            return ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for "
                            "base64-encoded hostname");

        salt_base64_len = ssh2_base64_encode(hosts->session,
                                             node->salt, node->salt_len,
                                             &saltalloc);
        if(!salt_base64_len) {
            SSH2_FREE(hosts->session, namealloc);
            return ssh2_err(hosts->session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for "
                            "base64-encoded salt");
        }

        required_size += salt_base64_len + name_base64_len + 7;
        /* |1| + | + ' ' + \n + \0 = 7 */

        if(required_size <= buflen) {
            if(node->comment && key_type_len)
                ssh2_snprintf(buf, buflen, "|1|%s|%s %s %s %s\n", saltalloc,
                              namealloc, key_type_name, node->key,
                              node->comment);
            else if(node->comment)
                ssh2_snprintf(buf, buflen, "|1|%s|%s %s %s\n", saltalloc,
                              namealloc, node->key, node->comment);
            else if(key_type_len)
                ssh2_snprintf(buf, buflen, "|1|%s|%s %s %s\n", saltalloc,
                              namealloc, key_type_name, node->key);
            else
                ssh2_snprintf(buf, buflen, "|1|%s|%s %s\n", saltalloc,
                              namealloc, node->key);
        }

        SSH2_FREE(hosts->session, namealloc);
        SSH2_FREE(hosts->session, saltalloc);
    }
    else {
        required_size += node->name_len + 3;
        /* ' ' + '\n' + \0 = 3 */

        if(required_size <= buflen) {
            if(node->comment && key_type_len)
                ssh2_snprintf(buf, buflen, "%s %s %s %s\n", node->name,
                              key_type_name, node->key, node->comment);
            else if(node->comment)
                ssh2_snprintf(buf, buflen, "%s %s %s\n", node->name, node->key,
                              node->comment);
            else if(key_type_len)
                ssh2_snprintf(buf, buflen, "%s %s %s\n", node->name,
                              key_type_name, node->key);
            else
                ssh2_snprintf(buf, buflen, "%s %s\n", node->name, node->key);
        }
    }

    /* we report the full length of the data with the trailing zero excluded */
    *outlen = required_size - 1;

    if(required_size <= buflen)
        return LIBSSH2_ERROR_NONE;
    else
        return ssh2_err(hosts->session, LIBSSH2_ERROR_BUFFER_TOO_SMALL,
                        "Known-host write buffer too small");
}

/*
 * Ask libssh2 to convert a known host to an output line for storage.
 *
 * Note that this function returns LIBSSH2_ERROR_BUFFER_TOO_SMALL if the given
 * output buffer is too small to hold the desired output.
 */
int libssh2_knownhost_writeline(LIBSSH2_KNOWNHOSTS *hosts,
                                struct libssh2_knownhost *known,
                                char *buffer, size_t buflen,
                                size_t *outlen, /* amount of written data */
                                int type)
{
    struct known_host *node;

    if(!hosts || !known)
        return LIBSSH2_ERROR_BAD_USE;

    if(known->magic != KNOWNHOST_MAGIC)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_INVAL,
                        "Invalid host information");

    node = known->node;

    return knownhost_writeline(hosts, node, buffer, buflen, outlen, type);
}

/*
 * Write hosts+key pairs to the given file.
 */
int libssh2_knownhost_writefile(LIBSSH2_KNOWNHOSTS *hosts,
                                const char *filename, int type)
{
    struct known_host *node;
    FILE *fp;
    int rc = LIBSSH2_ERROR_NONE;
    char buffer[4092];

    if(!hosts || !filename)
        return LIBSSH2_ERROR_BAD_USE;

    /* we only support this single file type for now, bail out on all other
       attempts */
    if(type != LIBSSH2_KNOWNHOST_FILE_OPENSSH)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_METHOD_NOT_SUPPORTED,
                        "Unsupported type of known-host information store");

    fp = ssh2_fopen(filename, FOPEN_WRITETEXT);
    if(!fp)
        return ssh2_err(hosts->session, LIBSSH2_ERROR_FILE,
                        "Failed to open file");

    for(node = ssh2_list_first(&hosts->head);
        node;
        node = ssh2_list_next(&node->node)) {
        size_t wrote = 0;
        size_t nwrote;
        rc = knownhost_writeline(hosts, node, buffer, sizeof(buffer), &wrote,
                                 type);
        if(rc)
            break;

        nwrote = fwrite(buffer, 1, wrote, fp);
        if(nwrote != wrote) {
            /* failed to write the whole thing, bail out */
            rc = ssh2_err(hosts->session, LIBSSH2_ERROR_FILE, "Write failed");
            break;
        }
    }
    fclose(fp);

    return rc;
}

/*
 * Traverse the internal list of known hosts. Pass NULL to 'prev' to get
 * the first one.
 *
 * Returns:
 * 0 if a fine host was stored in 'store'
 * 1 if end of hosts
 * [negative] on errors
 */
int libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS *hosts,
                          struct libssh2_knownhost **store,
                          struct libssh2_knownhost *prev)
{
    struct known_host *node;

    if(prev && prev->node) {
        /* we have a starting point */
        struct known_host *prev_node = prev->node;

        /* get the next node in the list */
        node = ssh2_list_next(&prev_node->node);
    }
    else {
        if(!hosts)
            return LIBSSH2_ERROR_BAD_USE;
        node = ssh2_list_first(&hosts->head);
    }

    if(!node)
        return 1;  /* no (more) node */

    if(!store)
        return LIBSSH2_ERROR_BAD_USE;

    *store = knownhost_to_external(node);

    return 0;
}
