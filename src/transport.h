#ifndef __LIBSSH2_TRANSPORT_H
#define __LIBSSH2_TRANSPORT_H

/* Copyright (C) 2007 The Written Word, Inc.  All rights reserved.
 * Copyright (C) 2009 by Daniel Stenberg
 * Author: Daniel Stenberg <daniel@haxx.se>
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
 *
 * This file handles reading and writing to the SECSH transport layer. RFC4253.
 */

#include "libssh2_priv.h"

/*
 * libssh2_transport_write
 *
 * Send a packet, encrypting it and adding a MAC code if necessary
 * Returns 0 on success, non-zero on failure.
 *
 * Returns PACKET_EAGAIN if it would block - and if it does so, you should
 * call this function again as soon as it is likely that more data can be
 * sent, and this function should then be called with the same argument set
 * (same data pointer and same data_len) until zero or failure is returned.
 *
 * NOTE: this function does not verify that 'data_len' is less than ~35000
 * which is what all implementations should support at least as packet size.
 * (RFC4253 section 6.1)
 */
int _libssh2_transport_write(LIBSSH2_SESSION * session, unsigned char *data,
                             unsigned long data_len);
/*
 * _libssh2_transport_read
 *
 * Collect a packet into the input brigade block only controls whether or not
 * to wait for a packet to start.
 *
 * Returns packet type added to input brigade (PACKET_NONE if nothing added),
 * or PACKET_FAIL on failure and PACKET_EAGAIN if it couldn't process a full
 * packet.
 */

/*
 * This function reads the binary stream as specified in chapter 6 of RFC4253
 * "The Secure Shell (SSH) Transport Layer Protocol"
 */
libssh2pack_t _libssh2_transport_read(LIBSSH2_SESSION * session);

#endif /* __LIBSSH2_TRANSPORT_H */
