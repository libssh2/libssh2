/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * OSS-Fuzz target: exercise the known_hosts file parser (knownhost.c).
 *
 * The known_hosts store is filled from files whose content is attacker-
 * or user-controlled: line splitting, host pattern lists, hashed
 * (|1|salt|hash) hostname decoding, base64 key blob decoding and key type
 * mapping all consume untrusted bytes. The fuzz input is used directly as
 * a known_hosts file, plus a second parse pass through
 * libssh2_knownhost_readline(), followed by a lookup and a write-line
 * round trip of whatever entry matched.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
#include "libssh2.h"
}

#define TMP_FILE "/tmp/libssh2_knownhost_fuzz"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_KNOWNHOSTS *hosts = NULL;
    struct libssh2_knownhost *store = NULL;
    FILE *fp = NULL;
    int rc;

    if(size < 1)
        return 0;

    rc = libssh2_init(0);

    if(rc) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 0;
    }

    session = libssh2_session_init();

    if(!session)
        goto EXIT_LABEL;

    hosts = libssh2_knownhost_init(session);

    if(!hosts)
        goto EXIT_LABEL;

    /* Write the fuzz input as a known_hosts file and parse it. */
    fp = fopen(TMP_FILE, "wb");

    if(!fp)
        goto EXIT_LABEL;

    fwrite(data, 1, size, fp);
    fclose(fp);
    fp = NULL;

    (void)libssh2_knownhost_readfile(hosts, TMP_FILE,
                                     LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    unlink(TMP_FILE);

    /* Second parse pass, line by line, through the readline entry point.
     * Feed only a bounded prefix so a single huge input cannot make this
     * loop dominate the run. */
    {
        size_t pos = 0;
        int lines = 0;

        while(pos < size && lines < 32) {
            const char *line = (const char *)data + pos;
            const char *nl = (const char *)memchr(line, '\n', size - pos);
            size_t len = nl ? (size_t)(nl - line) : (size_t)(size - pos);

            if(len)
                (void)libssh2_knownhost_readline(hosts, line, len,
                                                 LIBSSH2_KNOWNHOST_FILE_OPENSSH);
            if(!nl)
                break;
            pos += len + 1;
            lines++;
        }
    }

    /* Look up a fixed host+key against whatever was parsed. This drives
     * the matching logic (plain, comma lists and hashed hostnames) and
     * yields an entry for the write-back round trip. */
    {
        static const char key[] =
            "AAAAC3NzaC1lZDI1NTE5AAAAIGVsbF9ub3RfYV9yZWFsX2tleV92YWx1ZQ==";
        static const char host[] = "ssh.example.com";

        rc = libssh2_knownhost_checkp(hosts, host, 22,
                                      key, sizeof(key) - 1,
                                      LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                                      LIBSSH2_KNOWNHOST_KEY_ED25519,
                                      &store);

        if(rc == LIBSSH2_KNOWNHOST_CHECK_MATCH && store) {
            char out[1024];
            size_t outlen = 0;

            (void)libssh2_knownhost_writeline(hosts, store, out,
                                              sizeof(out), &outlen,
                                              LIBSSH2_KNOWNHOST_FILE_OPENSSH);
        }
    }

EXIT_LABEL:

    if(fp)
        fclose(fp);

    unlink(TMP_FILE);

    if(hosts)
        libssh2_knownhost_free(hosts);

    if(session)
        libssh2_session_free(session);

    return 0;
}
