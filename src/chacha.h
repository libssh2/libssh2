/* $OpenBSD: chacha.h,v 1.4 2016/08/27 04:04:56 guenther Exp $ */

/*
 * chacha-merged.c version 20080118
 * D. J. Bernstein
 * Public domain.
 * Copyright not intended 2024.
 *
 * SPDX-License-Identifier: SAX-PD-2.0
 */

#ifndef CHACHA_H
#define CHACHA_H

#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned int u32;

struct chacha_ctx {
    u32 input[16];
};

#define CHACHA_MINKEYLEN    16
#define CHACHA_NONCELEN     8
#define CHACHA_CTRLEN       8
#define CHACHA_STATELEN     (CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN     64

void chacha_keysetup(struct chacha_ctx *x, const u8 *k, u32 kbits);
void chacha_ivsetup(struct chacha_ctx *x, const u8 *iv, const u8 *ctr);
void chacha_encrypt_bytes(struct chacha_ctx *x, const u8 *m,
                          unsigned char *c, size_t bytes);

#endif /* CHACHA_H */
