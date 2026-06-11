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
    LIBSSH2_KNOWNHOSTS *kh;

    if(!size)
        return 0;

    libssh2_init(0);

    kh = libssh2_knownhost_init(NULL);
    if(!kh)
        return 0;

    libssh2_knownhost_readline(kh, (const char *)data, size,
                               LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    libssh2_knownhost_free(kh);
    libssh2_exit();

    return 0;
}
