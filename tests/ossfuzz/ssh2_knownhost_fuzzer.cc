/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Fuzz harness for libssh2 known-hosts line parser.
 *
 * Exercises libssh2_knownhost_readline() which parses lines from an OpenSSH
 * known_hosts file.  A single line may contain:
 *
 *   - A plain hostname or comma-separated list of hostnames
 *   - A hashed hostname of the form |1|<salt>|<hash>
 *   - An optional key-type token (e.g. "ssh-rsa", "ecdsa-sha2-nistp256")
 *   - A base64-encoded public key blob
 *   - An optional trailing comment
 *
 * All of these fields involve string parsing, base64 decoding, and
 * (for hashed hosts) HMAC computation - paths that process
 * attacker-controlled data in any deployment that calls
 * libssh2_knownhost_readfile() or libssh2_knownhost_readline().
 *
 * The harness requires no network access and uses only the public API.
 */
#include "libssh2.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_KNOWNHOSTS *hosts = NULL;

    if(size == 0)
        return 0;

    if(libssh2_init(0) != 0)
        goto cleanup;

    session = libssh2_session_init();
    if(!session)
        goto cleanup;

    hosts = libssh2_knownhost_init(session);
    if(!hosts)
        goto cleanup;

    /* Feed the raw fuzz bytes as a single known_hosts line.
     * libssh2_knownhost_readline() accepts a non-NUL-terminated buffer
     * (len is passed explicitly), so we do not need to copy or add a NUL. */
    libssh2_knownhost_readline(hosts,
                               (const char *)data, size,
                               LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    /* If the line parsed successfully an entry was added; also exercise the
     * write-line path over any entries that were stored. */
    {
        struct libssh2_knownhost *node = NULL;
        int grc = libssh2_knownhost_get(hosts, &node, NULL);
        while(grc == 0 && node) {
            char linebuf[4096];
            size_t linelen = 0;
            libssh2_knownhost_writeline(hosts, node,
                                        linebuf, sizeof(linebuf),
                                        &linelen,
                                        LIBSSH2_KNOWNHOST_FILE_OPENSSH);
            grc = libssh2_knownhost_get(hosts, &node, node);
        }
    }

cleanup:
    if(hosts)
        libssh2_knownhost_free(hosts);
    if(session) {
        libssh2_session_free(session);
    }
    libssh2_exit();
    return 0;
}
