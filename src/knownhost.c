/*
 * Copyright (c) 2009 by Daniel Stenberg
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

#include "libssh2.h"
#include "libssh2_priv.h"
#include "misc.h"

static void free_host(LIBSSH2_SESSION *session, struct known_host *entry)
{
    if(entry) {
        if(entry->key)
            LIBSSH2_FREE(session, entry->key);
        if(entry->salt)
            LIBSSH2_FREE(session, entry->salt);
        if(entry->name)
            LIBSSH2_FREE(session, entry->name);
        LIBSSH2_FREE(session, entry);
    }
}

/*
 * libssh2_knownhost_init
 *
 * Init a collection of known hosts. Returns the pointer to a collection.
 *
 */
LIBSSH2_API LIBSSH2_KNOWNHOSTS *
libssh2_knownhost_init(LIBSSH2_SESSION *session)
{
    LIBSSH2_KNOWNHOSTS *knh =
        LIBSSH2_ALLOC(session, sizeof(struct _LIBSSH2_KNOWNHOSTS));

    if(!knh)
        return NULL;

    knh->session = session;

    _libssh2_list_init(&knh->head);

    return knh;
}

/*
 * libssh2_knownhost_add
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
 *
 */

LIBSSH2_API int
libssh2_knownhost_add(LIBSSH2_KNOWNHOSTS *hosts,
                      char *host, char *salt,
                      char *key, size_t keylen,
                      int typemask)
{
    struct known_host *entry =
        LIBSSH2_ALLOC(hosts->session, sizeof(struct known_host));
    size_t hostlen = strlen(host);
    int rc = LIBSSH2_ERROR_ALLOC;
    char *ptr;
    unsigned int ptrlen;

    if(!entry)
        return rc;

    memset(entry, 0, sizeof(struct known_host));

    entry->typemask = typemask;

    switch(entry->typemask  & LIBSSH2_KNOWNHOST_TYPE_MASK) {
    case LIBSSH2_KNOWNHOST_TYPE_PLAIN:
    case LIBSSH2_KNOWNHOST_TYPE_CUSTOM:
        entry->name = LIBSSH2_ALLOC(hosts->session, hostlen+1);
        if(!entry)
            goto error;
        memcpy(entry->name, host, hostlen+1);
        break;
    case LIBSSH2_KNOWNHOST_TYPE_SHA1:
        rc = libssh2_base64_decode(hosts->session, &ptr, &ptrlen,
                                   host, hostlen);
        if(rc)
            goto error;
        entry->name = ptr;
        entry->name_len = ptrlen;

        rc = libssh2_base64_decode(hosts->session, &ptr, &ptrlen,
                                   salt, strlen(salt));
        if(rc)
            goto error;
        entry->salt = ptr;
        entry->salt_len = ptrlen;
        break;
    default:
        rc = LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;
        goto error;
    }

    if(typemask & LIBSSH2_KNOWNHOST_KEYENC_BASE64) {
        /* the provided key is base64 encoded already */
        if(!keylen)
            keylen = strlen(key);
        entry->key = LIBSSH2_ALLOC(hosts->session, keylen+1);
        if(!entry)
            goto error;
        memcpy(entry->key, key, keylen+1);
    }
    else {
        /* key is raw, we base64 encode it and store it as such */
        size_t nlen = _libssh2_base64_encode(hosts->session, key, keylen,
                                             &ptr);
        if(!nlen)
            goto error;

        entry->key = ptr;
    }

    /* add this new host to the big list of known hosts */
    _libssh2_list_add(&hosts->head, &entry->node);

    return LIBSSH2_ERROR_NONE;
  error:
    free_host(hosts->session, entry);
    return rc;
}

#define KNOWNHOST_MAGIC 0xdeadcafe
/*
 * knownhost_to_external()
 *
 * Copies data from the internal to the external representation struct.
 *
 */
static void knownhost_to_external(struct known_host *node,
                                  struct libssh2_knownhost *ext)
{
    if(ext) {
        ext->magic = KNOWNHOST_MAGIC;
        ext->node = node;
        ext->name = ((node->typemask & LIBSSH2_KNOWNHOST_TYPE_MASK) ==
                     LIBSSH2_KNOWNHOST_TYPE_PLAIN)? node->name:NULL;
        ext->key = node->key;
        ext->typemask = node->typemask;
    }
}

/*
 * libssh2_knownhost_check
 *
 * Check a host and its associated key against the collection of known hosts.
 *
 * The typemask is the type/format of the given host name and key
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
LIBSSH2_API int
libssh2_knownhost_check(LIBSSH2_KNOWNHOSTS *hosts,
                        char *host, char *key, size_t keylen,
                        int typemask,
                        struct libssh2_knownhost *knownhost)
{
    struct known_host *node = _libssh2_list_first(&hosts->head);
    struct known_host *badkey = NULL;
    int type = typemask & LIBSSH2_KNOWNHOST_TYPE_MASK;
    char *keyalloc = NULL;
    int rc = LIBSSH2_KNOWNHOST_CHECK_NOTFOUND;

    if(type == LIBSSH2_KNOWNHOST_TYPE_SHA1)
        /* we can't work with a sha1 as given input */
        return LIBSSH2_KNOWNHOST_CHECK_MISMATCH;

    if(!(typemask & LIBSSH2_KNOWNHOST_KEYENC_BASE64)) {
        /* we got a raw key input, convert it to base64 for the checks below */
        size_t nlen = _libssh2_base64_encode(hosts->session, key, keylen,
                                             &keyalloc);
        if(!nlen)
            return LIBSSH2_KNOWNHOST_CHECK_FAILURE;

        /* make the key point to this */
        key = keyalloc;
        keylen = nlen;
    }

    while (node) {
        int match = 0;
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
                /* when we have the sha1 version stored, we can use a plain
                   input to produce a hash to compare with the stored hash.
                */
                libssh2_hmac_ctx ctx;
                unsigned char hash[SHA_DIGEST_LENGTH];

                if(SHA_DIGEST_LENGTH != node->name_len) {
                    /* the name hash length must be the sha1 size or
                       we can't match it */
                    break;
                }
                libssh2_hmac_sha1_init(&ctx, node->salt, node->salt_len);
                libssh2_hmac_update(ctx, (unsigned char *)host, strlen(host));
                libssh2_hmac_final(ctx, hash);
                libssh2_hmac_cleanup(&ctx);

                if(!memcmp(hash, node->name, SHA_DIGEST_LENGTH))
                    /* this is a node we're interested in */
                    match = 1;
            }
            break;
        default: /* unsupported type */
            break;
        }
        if(match) {
            /* host name match, now compare the keys */
            if(!strcmp(key, node->key)) {
                /* they match! */
                knownhost_to_external(node, knownhost);
                badkey = NULL;
                rc = LIBSSH2_KNOWNHOST_CHECK_MATCH;
                break;
            }
            else {
                /* remember the first node that had a host match but a failed
                   key match since we continue our search from here */
                if(!badkey)
                    badkey = node;
            }
        }
        node= _libssh2_list_next(&node->node);
    }

    if(badkey) {
        /* key mismatch */
        knownhost_to_external(badkey, knownhost);
        rc = LIBSSH2_KNOWNHOST_CHECK_MISMATCH;
    }

    if(keyalloc)
        LIBSSH2_FREE(hosts->session, keyalloc);

    return rc;
}

/*
 * libssh2_knownhost_del
 *
 * Remove a host from the collection of known hosts.
 *
 */
LIBSSH2_API int
libssh2_knownhost_del(LIBSSH2_KNOWNHOSTS *hosts,
                      struct libssh2_knownhost *entry)
{
    struct known_host *node;
    if(!entry || (entry->magic != KNOWNHOST_MAGIC))
        /* check that this was retrieved the right way or get out */
        return -1;

    /* get the internal node pointer */
    node = entry->node;

    /* unlink from the list of all hosts */
    _libssh2_list_remove(&node->node);

    /* free all resources */
    free_host(hosts->session, node);

    /* clear the struct now since this host entry has been removed! */
    memset(entry, 0, sizeof(struct libssh2_knownhost));

    return 0;
}

/*
 * libssh2_knownhost_free
 *
 * Free an entire collection of known hosts.
 *
 */
LIBSSH2_API void
libssh2_knownhost_free(LIBSSH2_KNOWNHOSTS *hosts)
{
    struct known_host *node;
    struct known_host *next;

    for(node = _libssh2_list_first(&hosts->head); node; node = next) {
        next = _libssh2_list_next(&node->node);
        free_host(hosts->session, node);
    }
    LIBSSH2_FREE(hosts->session, hosts);
}

/*
 * hostline()
 *
 * Parse a single known_host line pre-split into host and key.
 *
 * Note: this function assumes that the 'host' pointer points into a temporary
 * buffer as it will write to it.
 */
static int hostline(LIBSSH2_KNOWNHOSTS *hosts,
                    char *host, size_t hostlen,
                    char *key, size_t keylen)
{
    char *p;
    char *salt = NULL;
    int rc;
    int type = LIBSSH2_KNOWNHOST_TYPE_PLAIN;
    char *sep = NULL;

    /* Figure out host format */
    if(strncmp(host, "|1|", 3)) {
        /* old style plain text: [name][,][ip-address]

           for the sake of simplicity, we add them as two hosts with the same
           key
         */
        sep = strchr(host, ',');
    }
    else {
        /* |1|[salt]|[hash] */
        type = LIBSSH2_KNOWNHOST_TYPE_SHA1;

        salt = &host[3]; /* skip the magic marker */

        /* this is where the salt starts, find the end of it */
        for(p = salt; *p && (*p != '|'); p++)
            ;

        if(*p=='|') {
            char *hash = NULL;
            *p=0; /* terminate the salt string */
            hash = p+1; /* the hash is after the separator */

            /* now make the host point to the hash */
            hostlen = strlen(hash);
            host = hash;
        }
        else
            return 0;
    }

    if(keylen < 20)
        return -1; /* TODO: better return code */

    switch(key[0]) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        type |= LIBSSH2_KNOWNHOST_KEY_RSA1;

        /* Note that the old-style keys (RSA1) aren't truly base64, but we
         * claim it is for now since we can get away with strcmp()ing the
         * entire anything anyway! We need to check and fix these to make them
         * work properly.
         */
        break;

    case 's': /* ssh-dss or ssh-rsa */
        if(!strncmp(key, "ssh-dss", 7))
            type |= LIBSSH2_KNOWNHOST_KEY_SSHDSS;
        else if(!strncmp(key, "ssh-rsa", 7))
            type |= LIBSSH2_KNOWNHOST_KEY_SSHRSA;
        else
            return -1; /* unknown */

        key += 7;
        keylen -= 7;

        /* skip whitespaces */
        while((*key ==' ') || (*key == '\t')) {
            key++;
            keylen--;
        }
        break;

    default: /* unknown key format */
        return -1;
    }

    if(sep) {
        /* this is the second host after the comma, add this first */
        char *ipaddr;
        *sep++ = 0; /* zero terminate the first host name here */
        ipaddr = sep;
        rc = libssh2_knownhost_add(hosts, ipaddr, salt, key, keylen,
                                   type | LIBSSH2_KNOWNHOST_KEYENC_BASE64);
        if(rc)
            return rc;
    }

    rc = libssh2_knownhost_add(hosts, host, salt, key, keylen,
                               type | LIBSSH2_KNOWNHOST_KEYENC_BASE64);

    return rc;
}

/*
 * libssh2_knownhost_readfile
 *
 * Read hosts+key pairs from a given file.
 *
 * Returns a negative value for error or number of successfully added hosts.
 *
 * Line format:
 *
 * <host> <key>
 *
 * Where the two parts can be created like:
 *
 * <host> can be either
 * <name> or <hash>
 *
 * <name> consists of
 * [name,address] or just [name] or just [address]
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

#define LIBSSH2_KNOWNHOST_FILE_OPENSSH 1

LIBSSH2_API int
libssh2_knownhost_readfile(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *filename, int type)
{
    FILE *file;
    int num = 0;
    char buf[2048];

    if(type != LIBSSH2_KNOWNHOST_FILE_OPENSSH)
        return LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;

    file = fopen(filename, "r");
    if(file) {
        char *cp;
        char *hostp;
        char *key;
        size_t hostlen;

        while(fgets(buf, sizeof(buf), file)) {
            cp = buf;

            /* skip leading whitespaces */
            while((*cp==' ') || (*cp == '\t'))
                cp++;

            if(!*cp || (*cp == '#') || (*cp == '\n'))
                /* comment or empty line */
                continue;

            /* the host part starts here */
            hostp = cp;

            /* move over the host to the separator */
            while(*cp && (*cp!=' ') && (*cp != '\t'))
                cp++;

            hostlen = cp - hostp;

            *cp++ = 0; /* terminate the host string here */

            /* the key starts after the whitespaces */
            while(*cp && ((*cp==' ') || (*cp == '\t')))
                cp++;

            if(!*cp)
                /* illegal line */
                continue;

            key = cp; /* the key starts here */

            while(*cp && (*cp != '\n'))
                cp++;

            /* zero terminate where the newline is */
            if(*cp == '\n')
                *cp = 0;

            /* deal with this one host+key line */
            if(!hostline(hosts, hostp, hostlen, key, strlen(key)))
                num++;
        }
        fclose(file);
    }
    else
        return -1;
    return num;
}

/*
 * libssh2_knownhost_writefile()
 *
 * Write hosts+key pairs to the given file.
 */
LIBSSH2_API int
libssh2_knownhost_writefile(LIBSSH2_KNOWNHOSTS *hosts,
                           const char *filename, int type)
{
    struct known_host *node;
    FILE *file;
    int rc = LIBSSH2_ERROR_NONE;

    /* we only support this single file type for now, bail out on all other
       attempts */
    if(type != LIBSSH2_KNOWNHOST_FILE_OPENSSH)
        return LIBSSH2_ERROR_METHOD_NOT_SUPPORTED;

    file = fopen(filename, "w");
    if(!file)
        return LIBSSH2_ERROR_FILE;

    for(node = _libssh2_list_first(&hosts->head);
        node;
        node= _libssh2_list_next(&node->node) ) {
        int tindex = (node->typemask & LIBSSH2_KNOWNHOST_KEY_MASK) >>
            LIBSSH2_KNOWNHOST_KEY_SHIFT;

        const char *types[4]={
            "", /* not used */
            "", /* this type has no name in the file */
            " ssh-rsa",
            " ssh-dss"
        };

        /* set the string used in the file */
        const char *type = types[tindex];

        if((node->typemask & LIBSSH2_KNOWNHOST_TYPE_MASK) ==
           LIBSSH2_KNOWNHOST_TYPE_SHA1) {
            char *namealloc;
            char *saltalloc;
            size_t nlen = _libssh2_base64_encode(hosts->session,
                                                 node->name, node->name_len,
                                                 &namealloc);
            if(!nlen) {
                rc = LIBSSH2_KNOWNHOST_CHECK_FAILURE;
                break;
            }
            nlen = _libssh2_base64_encode(hosts->session,
                                          node->salt, node->salt_len,
                                          &saltalloc);
            if(!nlen) {
                rc = LIBSSH2_KNOWNHOST_CHECK_FAILURE;
                free(namealloc);
                break;
            }
            fprintf(file, "|1|%s|%s%s %s\n", saltalloc, namealloc, type,
                    node->key);
            free(namealloc);
            free(saltalloc);
        }
        else {
            /* these types have the plain name */
            fprintf(file, "%s%s %s\n", node->name, type, node->key);
        }

    }
    fclose(file);

    return rc;
}


/*
 * libssh2_knownhost_get()
 *
 * Traverse the internal list of known hosts. Pass NULL to 'prev' to get
 * the first one.
 *
 * Returns:
 * 0 if a fine host was stored in 'store'
 * 1 if end of hosts
 * [negative] on errors
 */
LIBSSH2_API int
libssh2_knownhost_get(LIBSSH2_KNOWNHOSTS *hosts,
                      struct libssh2_knownhost *store,
                      struct libssh2_knownhost *oprev)
{
    struct known_host *node;
    if(oprev && oprev->node) {
        /* we have a starting point */
        struct known_host *prev = oprev->node;

        /* get the next node in the list */
        node = _libssh2_list_next(&prev->node);

    }
    else
        node = _libssh2_list_first(&hosts->head);

    if(!node)
        /* no (more) node */
        return 1;

    knownhost_to_external(node, store);

    return 0;
}
