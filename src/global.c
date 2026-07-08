/* Copyright (C) Lars Nordin <Lars.Nordin@SDlabs.se>
 * Copyright (C) Simon Josefsson <simon@josefsson.org>
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
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

static int ssh2_s_initialized = 0;
static int ssh2_s_init_flags = 0;

int libssh2_init(int flags)
{
    if(ssh2_s_initialized == 0 && !(flags & LIBSSH2_INIT_NO_CRYPTO))
        ssh2_crypto_init();

    ssh2_s_initialized++;
    ssh2_s_init_flags |= flags;

    return 0;
}

void libssh2_exit(void)
{
    if(ssh2_s_initialized == 0)
        return;

    ssh2_s_initialized--;

    if(ssh2_s_initialized == 0 &&
       !(ssh2_s_init_flags & LIBSSH2_INIT_NO_CRYPTO))
        ssh2_crypto_exit();
}

void ssh2_init_if_needed(void)
{
    if(ssh2_s_initialized == 0)
        (void)libssh2_init(0);
}
