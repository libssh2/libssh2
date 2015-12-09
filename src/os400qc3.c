/*
 * Copyright (C) 2015 Patrick Monnerat, D+H <patrick.monnerat@dh.com>
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

#ifdef LIBSSH2_OS400QC3 /* compile only if we build with OS/400 QC3 library */

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <alloca.h>
#include <sys/uio.h>

#include <arpa/inet.h>


#ifdef OS400_DEBUG
/* In debug mode, all system library errors cause an exception. */
#define set_EC_length(ec, length)   ((ec).Bytes_Provided =                  \
                                     (ec).Bytes_Available = 0)
#else
#define set_EC_length(ec, length)   ((ec).Bytes_Provided = (length))
#endif


/* Ensure va_list operations are not on an array. */
typedef struct {
    va_list     list;
}       valiststr;


typedef int (*loadkeyproc)(LIBSSH2_SESSION *session,
                           const unsigned char *data, unsigned int datalen,
                           const unsigned char *passphrase, void *loadkeydata);

/* Public key extraction data. */
typedef struct {
    const char *            method;
    const unsigned char *   data;
    unsigned int            length;
}       loadpubkeydata;


/* Support for ASN.1 elements. */

typedef struct {
    char *          header;         /* Pointer to header byte. */
    char *          beg;            /* Pointer to element data. */
    char *          end;            /* Pointer to 1st byte after element. */
    unsigned char   class;          /* ASN.1 element class. */
    unsigned char   tag;            /* ASN.1 element tag. */
    unsigned char   constructed;    /* Element is constructed. */
}       asn1Element;

#define ASN1_INTEGER        2
#define ASN1_BIT_STRING     3
#define ASN1_OCTET_STRING   4
#define ASN1_NULL           5
#define ASN1_OBJ_ID         6
#define ASN1_SEQ            16

#define ASN1_CONSTRUCTED    0x20

/* rsaEncryption OID: 1.2.840.113549.1.1.1 */
static unsigned char    OID_rsaEncryption[] =
                            {9, 40 + 2, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 1, 1};
static int  sshrsapubkey(LIBSSH2_SESSION *session, char **sshpubkey,
                         asn1Element *params, asn1Element *key,
                         const char *method);

#if LIBSSH2_DSA != 0
/* dsaEncryption OID: 1.2.840.10040.4.1 */
static unsigned char    OID_dsaEncryption[] =
                            {7, 40 + 2, 0x86, 0x48, 0xCE, 0x38, 4, 1};
static int  sshdsapubkey(LIBSSH2_SESSION *session, char **sshpubkey,
                         asn1Element *params, asn1Element *key,
                         const char *method);
#endif

/* Public key extraction support. */
static struct {
    unsigned char * oid;
    int             (*sshpubkey)(LIBSSH2_SESSION *session, char **pubkey,
                                 asn1Element *params, asn1Element *key,
                                 const char *method);
    const char *    method;
}       pka[] = {
#if LIBSSH2_RSA != 0
    {   OID_rsaEncryption,  sshrsapubkey,   "ssh-rsa"   },
#endif
#if LIBSSH2_DSA != 0
    {   OID_dsaEncryption,  sshdsapubkey,   "ssh-dss"   },
#endif
    {   NULL,               NULL,           NULL        }
};

/* Define ASCII strings. */
static const char   beginencprivkeyhdr[] =
                                    "-----BEGIN ENCRYPTED PRIVATE KEY-----";
static const char   endencprivkeyhdr[] = "-----END ENCRYPTED PRIVATE KEY-----";
static const char   beginprivkeyhdr[] = "-----BEGIN PRIVATE KEY-----";
static const char   endprivkeyhdr[] = "-----END PRIVATE KEY-----";
static const char   beginrsaprivkeyhdr[] = "-----BEGIN RSA PRIVATE KEY-----";
static const char   endrsaprivkeyhdr[] = "-----END RSA PRIVATE KEY-----";
static const char   fopenrmode[] = "r";
static const char   fopenrbmode[] = "rb";


/* The rest of character literals in this module are in EBCDIC. */
#pragma convert(37)

#include <qusec.h>
#include <qc3prng.h>
#include <qc3dtaen.h>
#include <qc3dtade.h>
#include <qc3ctx.h>
#include <qc3hash.h>
#include <qc3hmac.h>
#include <qc3pbext.h>
#include <qc3sigvr.h>
#include <qc3sigcl.h>
#include <qc3pbext.h>

static Qc3_Format_KEYD0100_T    nulltoken = {""};

static int      zero = 0;
static int      rsaprivate[] = { Qc3_RSA_Private };
static char     anycsp[] = { Qc3_Any_CSP };
static char     binstring[] = { Qc3_Bin_String };
static char     berstring[] = { Qc3_BER_String };
static char     qc3clear[] = { Qc3_Clear };

static const Qus_EC_t ecnull = {0};     /* Error causes an exception. */

static asn1Element  lastbytebitcount = {
    (char *) &zero, NULL, (char *) &zero + 1
};


/*******************************************************************
 *
 * OS/400 QC3 crypto-library backend: ASN.1 support.
 *
 *******************************************************************/

static char *
getASN1Element(asn1Element *elem, char *beg, char *end)
{
    unsigned char b;
    unsigned long len;
    asn1Element lelem;

    /* Get a single ASN.1 element into `elem', parse ASN.1 string at `beg'
     * ending at `end'.
     * Returns a pointer in source string after the parsed element, or NULL
     * if an error occurs.
     */

    if (beg >= end || !*beg)
        return NULL;

    /* Process header byte. */
    elem->header = beg;
    b = (unsigned char) *beg++;
    elem->constructed = (b & 0x20) != 0;
    elem->class = (b >> 6) & 3;
    b &= 0x1F;
    if (b == 0x1F)
        return NULL;            /* Long tag values not supported here. */
    elem->tag = b;

    /* Process length. */
    if (beg >= end)
        return NULL;
    b = (unsigned char) *beg++;
    if (!(b & 0x80))
        len = b;
    else if (!(b &= 0x7F)) {
        /* Unspecified length. Since we have all the data, we can determine the
         * effective length by skipping element until an end element is
         * found.
         */
        if (!elem->constructed)
            return NULL;
        elem->beg = beg;
        while (beg < end && *beg) {
            beg = getASN1Element(&lelem, beg, end);
        if (!beg)
            return NULL;
        }
        if (beg >= end)
            return NULL;
        elem->end = beg;
        return beg + 1;
    } else if (beg + b > end)
        return NULL;                        /* Does not fit in source. */
    else {
        /* Get long length. */
        len = 0;
        do {
            if (len & 0xFF000000L)
                return NULL;    /* Lengths > 32 bits are not supported. */
            len = (len << 8) | (unsigned char) *beg++;
        } while (--b);
    }
    if ((unsigned long) (end - beg) < len)
        return NULL;            /* Element data does not fit in source. */
    elem->beg = beg;
    elem->end = beg + len;
    return elem->end;
}

static asn1Element *
asn1_new(unsigned int type, unsigned int length)
{
    asn1Element *e;
    unsigned int hdrl = 2;
    unsigned int i;
    unsigned char *buf;

    e = (asn1Element *) malloc(sizeof *e);

    if (e) {
        if (length >= 0x80)
            for (i = length; i; i >>= 8)
                hdrl++;

        buf = (unsigned char *) malloc(hdrl + length);

        if (buf) {
            e->header = buf;
            e->beg = buf + hdrl;
            e->end = e->beg + length;
            e->class = (type >> 6) & 0x03;
            e->tag = type & 0x1F;
            e->constructed = (type >> 5) & 0x01;
            e->header[0] = type;

            if (length < 0x80)
                e->header[1] = length;
            else {
                e->header[1] = (hdrl - 2) | 0x80;
                do {
                    e->header[--hdrl] = length;
                    length >>= 8;
                } while (length);
            }
        } else {
            free((char *) e);
            e = NULL;
        }
    }

    return e;
}

static asn1Element *
asn1_new_from_bytes(const unsigned char *data, unsigned int length)
{
    asn1Element *e;
    asn1Element te;

    getASN1Element(&te,
                   (unsigned char *) data, (unsigned char *) data + length);
    e = asn1_new(te.tag, te.end - te.beg);

    if (e)
        memcpy(e->header, data, e->end - e->header);

    return e;
}

static void
asn1delete(asn1Element *e)
{
    if (e) {
        if (e->header)
            free((char *) e->header);
        free((char *) e);
    }
}

static asn1Element *
asn1uint(_libssh2_bn *bn)
{
    asn1Element *e;
    int bits;
    int length;
    unsigned char * p;

    if (!bn)
        return NULL;

    bits = _libssh2_bn_bits(bn);
    length = (bits + 8) >> 3;
    e = asn1_new(ASN1_INTEGER, length);

    if (e) {
        p = e->beg;
        if (!(bits & 0x07))
            *p++ = 0;
        _libssh2_bn_to_bin(bn, p);
    }

    return e;
}

static asn1Element *
asn1containerv(unsigned int type, valiststr args)
{
    valiststr va;
    asn1Element *e;
    asn1Element *p;
    unsigned char *bp;
    unsigned int length = 0;

    memcpy((char *) &va, (char *) &args, sizeof args);
    while ((p = va_arg(va.list, asn1Element *)))
        length += p->end - p->header;
    va_end(va.list);
    e = asn1_new(type, length);
    if (e) {
        bp = e->beg;
        while ((p = va_arg(args.list, asn1Element *))) {
            memcpy(bp, p->header, p->end - p->header);
            bp += p->end - p->header;
        }
    }
    return e;
}

/* VARARGS1 */
static asn1Element *
asn1container(unsigned int type, ...)
{
    valiststr va;
    asn1Element *e;

    va_start(va.list, type);
    e = asn1containerv(type, va);
    va_end(va.list);
    return e;
}

static asn1Element *
asn1bytes(unsigned int type, const unsigned char *bytes, unsigned int length)
{
    asn1Element *e;

    e = asn1_new(type, length);
    if (e && length)
        memcpy(e->beg, bytes, length);
    return e;
}

static asn1Element *
rsapublickey(_libssh2_bn *e, _libssh2_bn *m)
{
    asn1Element *publicexponent;
    asn1Element *modulus;
    asn1Element *rsapubkey;

    /* Build a PKCS#1 RSAPublicKey. */

    modulus = asn1uint(m);
    publicexponent = asn1uint(e);
    rsapubkey = asn1container(ASN1_SEQ | ASN1_CONSTRUCTED,
                              modulus, publicexponent, NULL);
    asn1delete(modulus);
    asn1delete(publicexponent);

    if (!modulus || !publicexponent) {
        asn1delete(rsapubkey);
        rsapubkey = NULL;
    }

    return rsapubkey;
}

static asn1Element *
rsaprivatekey(_libssh2_bn *e, _libssh2_bn *m, _libssh2_bn *d,
              _libssh2_bn *p, _libssh2_bn *q,
              _libssh2_bn *exp1, _libssh2_bn *exp2, _libssh2_bn *coeff)
{
    asn1Element *version;
    asn1Element *modulus;
    asn1Element *publicexponent;
    asn1Element *privateexponent;
    asn1Element *prime1;
    asn1Element *prime2;
    asn1Element *exponent1;
    asn1Element *exponent2;
    asn1Element *coefficient;
    asn1Element *rsaprivkey;

    /* Build a PKCS#1 RSAPrivateKey. */
    version = asn1bytes(ASN1_INTEGER, "\0", 1);
    modulus = asn1uint(m);
    publicexponent = asn1uint(e);
    privateexponent = asn1uint(d);
    prime1 = asn1uint(p);
    prime2 = asn1uint(q);
    exponent1 = asn1uint(exp1);
    exponent2 = asn1uint(exp2);
    coefficient = asn1uint(coeff);
    rsaprivkey = asn1container(ASN1_SEQ | ASN1_CONSTRUCTED, version, modulus,
                               publicexponent, privateexponent, prime1, prime2,
                               exponent1, exponent2, coefficient, NULL);
    asn1delete(version);
    asn1delete(modulus);
    asn1delete(publicexponent);
    asn1delete(privateexponent);
    asn1delete(prime1);
    asn1delete(prime2);
    asn1delete(exponent1);
    asn1delete(exponent2);
    asn1delete(coefficient);

    if (!version || !modulus || !publicexponent || !privateexponent ||
        !prime1 || !prime2 || !exponent1 || !exponent2 || !coefficient) {
        asn1delete(rsaprivkey);
        rsaprivkey = NULL;
    }

    return rsaprivkey;
}

static asn1Element *
subjectpublickeyinfo(asn1Element *pubkey, const unsigned char *algo,
                     asn1Element *parameters)
{
    asn1Element *subjpubkey;
    asn1Element *algorithm;
    asn1Element *algorithmid;
    asn1Element *subjpubkeyinfo;
    unsigned int algosize = *algo++;

    algorithm = asn1bytes(ASN1_OBJ_ID, algo, algosize);
    algorithmid = asn1container(ASN1_SEQ | ASN1_CONSTRUCTED,
                                algorithm, parameters, NULL);
    subjpubkey = asn1container(ASN1_BIT_STRING, &lastbytebitcount,
                               pubkey, NULL);
    subjpubkeyinfo = asn1container(ASN1_SEQ | ASN1_CONSTRUCTED,
                                   algorithmid, subjpubkey, NULL);
    asn1delete(algorithm);
    asn1delete(algorithmid);
    asn1delete(subjpubkey);
    if (!algorithm || !algorithmid || !subjpubkey) {
        asn1delete(subjpubkeyinfo);
        subjpubkeyinfo = NULL;
    }
    return subjpubkeyinfo;
}

static asn1Element *
rsasubjectpublickeyinfo(asn1Element *pubkey)
{
    asn1Element *parameters;
    asn1Element *subjpubkeyinfo;

    parameters = asn1bytes(ASN1_NULL, NULL, 0);
    subjpubkeyinfo = subjectpublickeyinfo(pubkey,
                                          OID_rsaEncryption, parameters);
    asn1delete(parameters);
    if (!parameters) {
        asn1delete(subjpubkeyinfo);
        subjpubkeyinfo = NULL;
    }
    return subjpubkeyinfo;
}

static asn1Element *
privatekeyinfo(asn1Element *privkey, const unsigned char *algo,
               asn1Element *parameters)
{
    asn1Element *version;
    asn1Element *privatekey;
    asn1Element *algorithm;
    asn1Element *privatekeyalgorithm;
    asn1Element *privkeyinfo;
    unsigned int algosize = *algo++;

    /* Build a PKCS#8 PrivateKeyInfo. */
    version = asn1bytes(ASN1_INTEGER, "\0", 1);
    algorithm = asn1bytes(ASN1_OBJ_ID, algo, algosize);
    privatekeyalgorithm = asn1container(ASN1_SEQ | ASN1_CONSTRUCTED,
                                        algorithm, parameters, NULL);
    privatekey = asn1container(ASN1_OCTET_STRING, privkey, NULL);
    privkeyinfo = asn1container(ASN1_SEQ | ASN1_CONSTRUCTED, version,
                                privatekeyalgorithm, privatekey, NULL);
    asn1delete(version);
    asn1delete(algorithm);
    asn1delete(privatekeyalgorithm);
    if (!version || !algorithm || !privatekeyalgorithm) {
        asn1delete(privkeyinfo);
        privkeyinfo = NULL;
    }
    return privkeyinfo;
}

static asn1Element *
rsaprivatekeyinfo(asn1Element *privkey)
{
    asn1Element *parameters;
    asn1Element *privkeyinfo;

    parameters = asn1bytes(ASN1_NULL, NULL, 0);
    privkeyinfo = privatekeyinfo(privkey, OID_rsaEncryption, parameters);
    asn1delete(parameters);
    if (!parameters) {
        asn1delete(privkeyinfo);
        privkeyinfo = NULL;
    }
    return privkeyinfo;
}

/*******************************************************************
 *
 * OS/400 QC3 crypto-library backend: big numbers support.
 *
 *******************************************************************/


_libssh2_bn *
_libssh2_bn_init(void)
{
    _libssh2_bn *bignum;

    bignum = (_libssh2_bn *) malloc(sizeof *bignum);
    if (bignum) {
        bignum->bignum = NULL;
        bignum->length = 0;
    }

    return bignum;
}

void
_libssh2_bn_free(_libssh2_bn *bn)
{
    if (bn) {
        if (bn->bignum) {
#ifdef LIBSSH2_CLEAR_MEMORY
            if (bn->length)
                memset((char *) bn->bignum, 0, bn->length);
#endif
            free(bn->bignum);
        }

        free((char *) bn);
    }
}

static int
_libssh2_bn_resize(_libssh2_bn *bn, size_t newlen)
{
    unsigned char *bignum;

    if (!bn)
        return -1;
    if (newlen == bn->length)
        return 0;

    if (!bn->bignum)
        bignum = (unsigned char *) malloc(newlen);
    else {
#ifdef LIBSSH2_CLEAR_MEMORY
        if (newlen < bn->length)
            memset((char *) bn->bignum + newlen, 0, bn->length - newlen);
#endif
        if (!newlen) {
            free((char *) bn->bignum);
            bn->bignum = NULL;
            bn->length = 0;
            return 0;
        }
        bignum = (unsigned char *) realloc((char *) bn->bignum, newlen);
    }

    if (!bignum)
        return -1;

    if (newlen > bn->length)
        memset((char *) bignum + bn->length, 0, newlen - bn->length);

    bn->bignum = bignum;
    bn->length = newlen;
    return 0;
}

unsigned long
_libssh2_bn_bits(_libssh2_bn *bn)
{
    unsigned int i;
    unsigned char b;

    if (bn && bn->bignum) {
        for (i = bn->length; i--;)
            if ((b = bn->bignum[i])) {
                i *= 8;
                do {
                    i++;
                } while (b >>= 1);
                return i;
            }
    }

    return 0;
}

int
_libssh2_bn_from_bin(_libssh2_bn *bn, int len, const unsigned char *val)
{
    int i;

    if (!bn || (len && !val))
        return -1;

    for (; len && !*val; len--)
        val++;

    if (_libssh2_bn_resize(bn, len))
        return -1;

    for (i = len; i--;)
        bn->bignum[i] = *val++;

    return 0;
}

int
_libssh2_bn_set_word(_libssh2_bn *bn, unsigned long val)
{
    val = htonl(val);
    return _libssh2_bn_from_bin(bn, sizeof val, (unsigned char *) &val);
}

int
_libssh2_bn_to_bin(_libssh2_bn *bn, unsigned char *val)
{
    int i;

    if (!bn || !val)
        return -1;

    for (i = bn->length; i--;)
        *val++ = bn->bignum[i];

    return 0;
}

static int
_libssh2_bn_from_bn(_libssh2_bn *to, _libssh2_bn *from)
{
    int i;

    if (!to || !from)
        return -1;

    if (_libssh2_bn_resize(to, from->length))
        return -1;

    for (i = to->length; i--;)
        to->bignum[i] = from->bignum[i];

    return 0;
}

void
_libssh2_random(unsigned char *buf, int len)
{
    Qc3GenPRNs(buf, len,
        Qc3PRN_TYPE_NORMAL, Qc3PRN_NO_PARITY, (char *) &ecnull);
}

int
_libssh2_bn_rand(_libssh2_bn *bn, int bits, int top, int bottom)
{
    int len;
    int i;

    if (!bn || bits <= 0)
        return -1;
    len = (bits + 7) >> 3;
    if (_libssh2_bn_resize(bn, len))
        return -1;
    _libssh2_random(bn->bignum, len);
    i = ((bits - 1) & 07) + 1;
    bn->bignum[len - 1] &= (1 << i) - 1;
    switch (top) {
    case 1:
        if (bits > 1)
            if (i > 1)
                bn->bignum[len - 1] |= 1 << (i - 2);
            else
                bn->bignum[len - 2] |= 0x80;
        /* Fall into. */
    case 0:
        bn->bignum[len - 1] |= 1 << (i - 1);
        break;
    }
    if (bottom)
        *bn->bignum |= 0x01;
    return 0;
}

static int
_libssh2_bn_lshift(_libssh2_bn *bn)
{
    int i;
    int c = 0;

    if (!bn)
        return -1;

    if (_libssh2_bn_resize(bn, (_libssh2_bn_bits(bn) + 8) >> 3))
        return -1;

    for (i = 0; i < bn->length; i++) {
        if (bn->bignum[i] & 0x80)
            c |= 0x02;
        bn->bignum[i] = (bn->bignum[i] << 1) | (c & 0x01);
        c >>= 1;
    }

    return 0;
}

static int
_libssh2_bn_rshift(_libssh2_bn *bn)
{
    int i;
    int c = 0;

    if (!bn)
        return -1;

    for (i = bn->length; i--;) {
        if (bn->bignum[i] & 0x01)
            c |= 0x100;
        bn->bignum[i] = (bn->bignum[i] >> 1) | (c & 0x80);
        c >>= 1;
    }

    if (_libssh2_bn_resize(bn, (_libssh2_bn_bits(bn) + 7) >> 3))
        return -1;

    return 0;
}

static void
_libssh2_bn_swap(_libssh2_bn *bn1, _libssh2_bn *bn2)
{
    _libssh2_bn t = *bn1;

    *bn1 = *bn2;
    *bn2 = t;
}

static int
_libssh2_bn_subtract(_libssh2_bn *d, _libssh2_bn *bn1, _libssh2_bn *bn2)
{
    int c = 0;
    int i;

    if (bn1->length < bn2->length)
        return -1;

    if (_libssh2_bn_resize(d, bn1->length))
        return -1;

    for (i = 0; i < bn2->length; i++) {
        c += (int) bn1->bignum[i] - (int) bn2->bignum[i];
        d->bignum[i] = c;
        c = c < 0? -1: 0;
    }

    for (; c && i < bn1->length; i++) {
        c += (int) bn1->bignum[i];
        d->bignum[i] = c;
        c = c < 0? -1: 0;
    }

    if (_libssh2_bn_resize(d, (_libssh2_bn_bits(d) + 7) >> 3))
        return -1;

    return c;
}

int
_libssh2_os400qc3_bn_mod_exp(_libssh2_bn *r, _libssh2_bn *a, _libssh2_bn *p,
                             _libssh2_bn *m)
{
    _libssh2_bn *mp;
    _libssh2_bn *rp;
    asn1Element *rsapubkey;
    asn1Element *subjpubkeyinfo;
    unsigned char *av;
    unsigned char *rv;
    char *keydbuf;
    Qc3_Format_ALGD0400_T algd;
    Qc3_Format_KEYD0200_T *keyd;
    Qus_EC_t errcode;
    int sc;
    int outlen;
    int ret = -1;

    /* There is no support for this function in the Qc3 crypto-library.
       Since a RSA encryption performs this function, we can emulate it
       by creating an RSA public key in ASN.1 SubjectPublicKeyInfo format
       from p (exponent) and m (modulus) and encrypt a with this key. The
       encryption output is the function result.
       Problem: the Qc3EncryptData procedure only succeeds if the data bit
       count is less than the modulus bit count. To satisfy this condition,
       we multiply the modulus by a power of two and adjust the result
       accordingly. */

    if (!r || !a || !p)
        return ret;
 
    mp = _libssh2_bn_init();
    if (!mp)
        return ret;
    if (_libssh2_bn_from_bn(mp, m)) {
        _libssh2_bn_free(mp);
        return ret;
    }
    for (sc = 0; _libssh2_bn_bits(mp) <= 8 * a->length; sc++)
        if (_libssh2_bn_lshift(mp)) {
            _libssh2_bn_free(mp);
            return ret;
        }

    rsapubkey = rsapublickey(p, mp);
    subjpubkeyinfo = rsasubjectpublickeyinfo(rsapubkey);
    asn1delete(rsapubkey);

    if (!rsapubkey || !subjpubkeyinfo) {
        asn1delete(rsapubkey);
        asn1delete(subjpubkeyinfo);
        _libssh2_bn_free(mp);
        return ret;
    }

    av = (unsigned char *) alloca(a->length);
    rv = (unsigned char *) alloca(mp->length);
    keydbuf = alloca(sizeof *keyd +
                     subjpubkeyinfo->end - subjpubkeyinfo->header);

    if (av && rv && keydbuf) {
        _libssh2_bn_to_bin(a, av);
        algd.Public_Key_Alg = Qc3_RSA;
        algd.PKA_Block_Format = Qc3_Zero_Pad;
        memset(algd.Reserved, 0, sizeof algd.Reserved);
        algd.Signing_Hash_Alg = 0;
        keyd = (Qc3_Format_KEYD0200_T *) keydbuf;
        keyd->Key_Type = Qc3_RSA_Public;
        keyd->Key_String_Len = subjpubkeyinfo->end - subjpubkeyinfo->header;
        keyd->Key_Format = Qc3_BER_String;
        memset(keyd->Reserved, 0, sizeof keyd->Reserved);
        memcpy(keydbuf + sizeof *keyd, subjpubkeyinfo->header,
               keyd->Key_String_Len);
        set_EC_length(errcode, sizeof errcode);
        Qc3EncryptData(av, (int *) &a->length, Qc3_Data, (char *) &algd,
                       Qc3_Alg_Public_Key, keydbuf, Qc3_Key_Parms, anycsp,
                       NULL, rv, (int *) &mp->length, &outlen, &errcode);
        if (!errcode.Bytes_Available) {
            _libssh2_bn_from_bin(r, outlen, rv);
            if (!sc)
                ret = 0;
            else {
                rp = _libssh2_bn_init();
                if (rp) {
                    do {
                        _libssh2_bn_rshift(mp);
                        if (!_libssh2_bn_subtract(rp, r, mp))
                            _libssh2_bn_swap(r, rp);
                    } while (--sc);
                    _libssh2_bn_free(rp);
                    ret = 0;
                }
            }
        }
    }
    asn1delete(subjpubkeyinfo);
    _libssh2_bn_free(mp);
    return ret;
}


/*******************************************************************
 *
 * OS/400 QC3 crypto-library backend: crypto context support.
 *
 *******************************************************************/

static _libssh2_os400qc3_crypto_ctx *
libssh2_init_crypto_ctx(_libssh2_os400qc3_crypto_ctx *ctx)
{
    if (!ctx)
        ctx = (_libssh2_os400qc3_crypto_ctx *) malloc(sizeof *ctx);

    if (ctx) {
        memset((char *) ctx, 0, sizeof *ctx);
        ctx->hash.Final_Op_Flag = Qc3_Continue;
    }

    return ctx;
}

static int
null_token(const char *token)
{
    return !memcmp(token, nulltoken.Key_Context_Token,
                   sizeof nulltoken.Key_Context_Token);
}

void
_libssh2_os400qc3_crypto_dtor(_libssh2_os400qc3_crypto_ctx *x)
{
    if (!null_token(x->hash.Alg_Context_Token)) {
        Qc3DestroyAlgorithmContext(x->hash.Alg_Context_Token, (char *) &ecnull);
        memset(x->hash.Alg_Context_Token, 0, sizeof x->hash.Alg_Context_Token);
    }
    if (!null_token(x->key.Key_Context_Token)) {
        Qc3DestroyKeyContext(x->key.Key_Context_Token, (char *) &ecnull);
        memset(x->key.Key_Context_Token, 0, sizeof x->key.Key_Context_Token);
    }
}

/*******************************************************************
 *
 * OS/400 QC3 crypto-library backend: hash algorithms support.
 *
 *******************************************************************/

int
libssh2_os400qc3_hash_init(Qc3_Format_ALGD0100_T *x, unsigned int algorithm)
{
    Qc3_Format_ALGD0500_T algd;
    Qus_EC_t errcode;

    if (!x)
        return 0;

    memset((char *) x, 0, sizeof *x);
    x->Final_Op_Flag = Qc3_Continue;
    algd.Hash_Alg = algorithm;
    set_EC_length(errcode, sizeof errcode);
    Qc3CreateAlgorithmContext((char *) &algd, Qc3_Alg_Hash,
                              x->Alg_Context_Token, &errcode);
    return errcode.Bytes_Available? 0: 1;
}

void
libssh2_os400qc3_hash_update(Qc3_Format_ALGD0100_T *ctx,
                             unsigned char *data, int len)
{
    char dummy[64];

    Qc3CalculateHash((char *) data, &len, Qc3_Data, (char *) ctx,
                     Qc3_Alg_Token, anycsp, NULL, dummy, (char *) &ecnull);
}

void
libssh2_os400qc3_hash_final(Qc3_Format_ALGD0100_T *ctx, unsigned char *out)
{
    char data;

    ctx->Final_Op_Flag = Qc3_Final;
    Qc3CalculateHash(&data, &zero, Qc3_Data, (char *) ctx, Qc3_Alg_Token,
                     anycsp, NULL, (char *) out, (char *) &ecnull);
    Qc3DestroyAlgorithmContext(ctx->Alg_Context_Token, (char *) &ecnull);
    memset(ctx->Alg_Context_Token, 0, sizeof ctx->Alg_Context_Token);
}

int
libssh2_os400qc3_hash(const unsigned char *message, unsigned long len,
                      unsigned char *out, unsigned int algo)
{
    Qc3_Format_ALGD0100_T ctx;

    if (!libssh2_os400qc3_hash_init(&ctx, algo))
        return 1;

    libssh2_os400qc3_hash_update(&ctx, (unsigned char *) message, len);
    libssh2_os400qc3_hash_final(&ctx, out);
    return 0;
}

void
libssh2_os400qc3_hmac_init(_libssh2_os400qc3_crypto_ctx *ctx,
                           int algo, void *key, int keylen)
{
    libssh2_os400qc3_hash_init(&ctx->hash, algo);
    Qc3CreateKeyContext((char *) key, &keylen, binstring, &algo, qc3clear,
                        NULL, NULL, ctx->key.Key_Context_Token,
                        (char *) &ecnull);
}

void
libssh2_os400qc3_hmac_update(_libssh2_os400qc3_crypto_ctx *ctx,
                             unsigned char *data, int len)
{
    char dummy[64];

    Qc3CalculateHMAC((char *) data, &len, Qc3_Data, (char *) &ctx->hash,
                     Qc3_Alg_Token, ctx->key.Key_Context_Token, Qc3_Key_Token,
                     anycsp, NULL, dummy, (char *) &ecnull);
}

void
libssh2_os400qc3_hmac_final(_libssh2_os400qc3_crypto_ctx *ctx,
                            unsigned char *out)
{
    char data;

    ctx->hash.Final_Op_Flag = Qc3_Final;
    Qc3CalculateHMAC((char *) data, &zero, Qc3_Data, (char *) &ctx->hash,
                     Qc3_Alg_Token, ctx->key.Key_Context_Token, Qc3_Key_Token,
                     anycsp, NULL, (char *) out, (char *) &ecnull);
}


/*******************************************************************
 *
 * OS/400 QC3 crypto-library backend: cipher algorithms support.
 *
 *******************************************************************/

int
_libssh2_cipher_init(_libssh2_cipher_ctx *h, _libssh2_cipher_type(algo),
                     unsigned char *iv, unsigned char *secret, int encrypt)
{
    Qc3_Format_ALGD0200_T algd;
    Qus_EC_t errcode;

    (void) encrypt;

    if (!h)
        return -1;

    libssh2_init_crypto_ctx(h);
    algd.Block_Cipher_Alg = algo.algo;
    algd.Block_Length = algo.size;
    algd.Mode = algo.mode;
    algd.Pad_Option = Qc3_No_Pad;
    algd.Pad_Character = 0;
    algd.Reserved = 0;
    algd.MAC_Length = 0;
    algd.Effective_Key_Size = 0;
    memset(algd.Init_Vector, 0 , sizeof algd.Init_Vector);
    if (algo.mode != Qc3_ECB && algo.size)
        memcpy(algd.Init_Vector, iv, algo.size);
    set_EC_length(errcode, sizeof errcode);
    Qc3CreateAlgorithmContext((char *) &algd, algo.fmt,
                              h->hash.Alg_Context_Token, &errcode);
    if (errcode.Bytes_Available)
        return -1;
    Qc3CreateKeyContext((char *) secret, &algo.keylen, binstring,
                        &algo.algo, qc3clear, NULL, NULL,
                        h->key.Key_Context_Token, (char *) &errcode);
    if (errcode.Bytes_Available) {
        _libssh2_os400qc3_crypto_dtor(h);
        return -1;
    }

    return 0;
}

int
_libssh2_cipher_crypt(_libssh2_cipher_ctx *ctx,
                      _libssh2_cipher_type(algo),
                      int encrypt, unsigned char *block, size_t blocksize)
{
    Qus_EC_t errcode;
    int outlen;
    int blksize = blocksize;

    (void) algo;

    set_EC_length(errcode, sizeof errcode);
    if (encrypt)
        Qc3EncryptData((char *) block, &blksize, Qc3_Data,
                       ctx->hash.Alg_Context_Token, Qc3_Alg_Token,
                       ctx->key.Key_Context_Token, Qc3_Key_Token, anycsp, NULL,
                       (char *) block, &blksize, &outlen, (char *) &errcode);
    else
        Qc3DecryptData((char *) block, &blksize,
                       ctx->hash.Alg_Context_Token, Qc3_Alg_Token,
                       ctx->key.Key_Context_Token, Qc3_Key_Token, anycsp, NULL,
                       (char *) block, &blksize, &outlen, (char *) &errcode);

    return errcode.Bytes_Available? -1: 0;
}


/*******************************************************************
 *
 * OS/400 QC3 crypto-library backend: RSA support.
 *
 *******************************************************************/

int
_libssh2_rsa_new(libssh2_rsa_ctx **rsa,
                 const unsigned char *edata, unsigned long elen,
                 const unsigned char *ndata, unsigned long nlen,
                 const unsigned char *ddata, unsigned long dlen,
                 const unsigned char *pdata, unsigned long plen,
                 const unsigned char *qdata, unsigned long qlen,
                 const unsigned char *e1data, unsigned long e1len,
                 const unsigned char *e2data, unsigned long e2len,
                 const unsigned char *coeffdata, unsigned long coefflen)
{
    libssh2_rsa_ctx *ctx;
    _libssh2_bn *e = _libssh2_bn_init_from_bin();
    _libssh2_bn *n = _libssh2_bn_init_from_bin();
    _libssh2_bn *d = NULL;
    _libssh2_bn *p = NULL;
    _libssh2_bn *q = NULL;
    _libssh2_bn *e1 = NULL;
    _libssh2_bn *e2 = NULL;
    _libssh2_bn *coeff = NULL;
    asn1Element *key = NULL;
    asn1Element *structkey = NULL;
    Qc3_Format_ALGD0400_T algd;
    Qus_EC_t errcode;
    int keytype;
    int ret = 0;
    int i;

    ctx = libssh2_init_crypto_ctx(NULL);
    if (!ctx)
        ret = -1;
    if (!ret) {
        _libssh2_bn_from_bin(e, elen, edata);
        _libssh2_bn_from_bin(n, nlen, ndata);
        if (!e || !n)
            ret = -1;
    }
    if (!ret && ddata) {
        /* Private key. */
        d = _libssh2_bn_init_from_bin();
        _libssh2_bn_from_bin(d, dlen, ddata);
        p = _libssh2_bn_init_from_bin();
        _libssh2_bn_from_bin(p, plen, pdata);
        q = _libssh2_bn_init_from_bin();
        _libssh2_bn_from_bin(q, qlen, qdata);
        e1 = _libssh2_bn_init_from_bin();
        _libssh2_bn_from_bin(e1, e1len, e1data);
        e2 = _libssh2_bn_init_from_bin();
        _libssh2_bn_from_bin(e2, e2len, e2data);
        coeff = _libssh2_bn_init_from_bin();
        _libssh2_bn_from_bin(coeff, coefflen, coeffdata);
        if (!d || !p || !q ||!e1 || !e2 || !coeff)
            ret = -1;

        if (!ret) {
            /* Build a PKCS#8 private key. */
            key = rsaprivatekey(e, n, d, p, q, e1, e2, coeff);
            structkey = rsaprivatekeyinfo(key);
        }
        keytype = Qc3_RSA_Private;
    } else if (!ret) {
        key = rsapublickey(e, n);
        structkey = rsasubjectpublickeyinfo(key);
        keytype = Qc3_RSA_Public;
    }
    if (!key || !structkey)
        ret = -1;

    set_EC_length(errcode, sizeof errcode);

    if (!ret) {
        /* Create the algorithm context. */
        algd.Public_Key_Alg = Qc3_RSA;
        algd.PKA_Block_Format = Qc3_PKCS1_01;
        memset(algd.Reserved, 0, sizeof algd.Reserved);
        algd.Signing_Hash_Alg = Qc3_SHA1;
        Qc3CreateAlgorithmContext((char *) &algd, Qc3_Alg_Public_Key,
                                  ctx->hash.Alg_Context_Token, &errcode);
        if (errcode.Bytes_Available)
            ret = -1;
        ctx->hash.Final_Op_Flag = Qc3_Continue;
    }

    /* Create the key context. */
    if (!ret) {
        i = structkey->end - structkey->header;
        Qc3CreateKeyContext(structkey->header, &i, berstring, &keytype,
                            qc3clear, NULL, NULL, ctx->key.Key_Context_Token,
                            (char *) &errcode);
        if (errcode.Bytes_Available)
            ret = -1;
    }

    _libssh2_bn_free(e);
    _libssh2_bn_free(n);
    _libssh2_bn_free(d);
    _libssh2_bn_free(p);
    _libssh2_bn_free(q);
    _libssh2_bn_free(e1);
    _libssh2_bn_free(e2);
    _libssh2_bn_free(coeff);
    asn1delete(key);
    asn1delete(structkey);
    if (ret && ctx) {
        _libssh2_rsa_free(ctx);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
}

static int
oidcmp(const asn1Element *e, const unsigned char *oid)
{
    int i = e->end - e->beg - *oid++;

    if (*e->header != ASN1_OBJ_ID)
        return -2;
    if (!i)
        i = memcmp(e->beg, oid, oid[-1]);
    return i;
}

static int
rsapkcs8privkey(LIBSSH2_SESSION *session,
                const unsigned char *data, unsigned int datalen,
                const unsigned char *passphrase, void *loadkeydata)
{
    libssh2_rsa_ctx *ctx = (libssh2_rsa_ctx *) loadkeydata;
    Qus_EC_t errcode;

    set_EC_length(errcode, sizeof errcode);
    Qc3CreateKeyContext((unsigned char *) data, (int *) &datalen, berstring,
                        rsaprivate, qc3clear, NULL, NULL,
                        ctx->key.Key_Context_Token, (char *) &errcode);
    return errcode.Bytes_Available? -1: 0;
}

static char *
storewithlength(char *p, const char *data, int length)
{
    _libssh2_htonu32(p, length);
    if (length)
        memcpy(p + 4, data, length);
    return p + 4 + length;
}

static int
sshrsapubkey(LIBSSH2_SESSION *session, char **sshpubkey,
             asn1Element *params, asn1Element *key, const char *method)
{
    int methlen = strlen(method);
    asn1Element keyseq;
    asn1Element m;
    asn1Element e;
    int len;
    char *cp;

    if (getASN1Element(&keyseq, key->beg + 1, key->end) != key->end ||
        *keyseq.header != (ASN1_SEQ | ASN1_CONSTRUCTED))
        return -1;
    if (!getASN1Element(&m, keyseq.beg, keyseq.end) ||
        *m.header != ASN1_INTEGER)
        return -1;
    if (getASN1Element(&e, m.end, keyseq.end) != keyseq.end ||
        *e.header != ASN1_INTEGER)
        return -1;
    len = 4 + methlen + 4 + (e.end - e.beg) + 4 + (m.end - m.beg);
    cp = LIBSSH2_ALLOC(session, len);
    if (!cp)
        return -1;
    *sshpubkey = cp;
    cp = storewithlength(cp, method, methlen);
    cp = storewithlength(cp, e.beg, e.end - e.beg);
    cp = storewithlength(cp, m.beg, m.end - m.beg);
    return len;
}

static int
rsapkcs8pubkey(LIBSSH2_SESSION *session,
               const unsigned char *data, unsigned int datalen,
               const unsigned char *passphrase, void *loadkeydata)
{
    loadpubkeydata *p = (loadpubkeydata *) loadkeydata;
    char *buf;
    int len;
    char *cp;
    int i;
    asn1Element subjpubkeyinfo;
    asn1Element algorithmid;
    asn1Element algorithm;
    asn1Element subjpubkey;
    asn1Element parameters;
    Qus_EC_t errcode;

    if (!(buf = alloca(datalen)))
        return -1;
    set_EC_length(errcode, sizeof errcode);
    Qc3ExtractPublicKey((char *) data, (int *) &datalen, berstring, qc3clear,
                        NULL, NULL, buf, (int *) &datalen, &len, &errcode);
    if (errcode.Bytes_Available)
        return -1;
    /* Get the algorithm OID and key data from SubjectPublicKeyInfo. */
    if (getASN1Element(&subjpubkeyinfo, buf, buf + len) != buf + len ||
        *subjpubkeyinfo.header != (ASN1_SEQ | ASN1_CONSTRUCTED))
        return -1;
    cp = getASN1Element(&algorithmid, subjpubkeyinfo.beg, subjpubkeyinfo.end);
    if (!cp || *algorithmid.header != (ASN1_SEQ | ASN1_CONSTRUCTED))
        return -1;
    if (!getASN1Element(&algorithm, algorithmid.beg, algorithmid.end) ||
        *algorithm.header != ASN1_OBJ_ID)
        return -1;
    if (getASN1Element(&subjpubkey, cp, subjpubkeyinfo.end) !=
        subjpubkeyinfo.end || *subjpubkey.header != ASN1_BIT_STRING)
        return -1;
    /* Check for supported algorithm. */
    for (i = 0; pka[i].oid; i++)
        if (!oidcmp(&algorithm, pka[i].oid)) {
            len = (*pka[i].sshpubkey)(session, &p->data, &algorithmid,
                                      &subjpubkey, pka[i].method);
            if (len < 0)
                return -1;
            p->length = len;
            p->method = pka[i].method;
            return 0;
        }
    return -1;                              /* Algorithm not supported. */
}

static int
pkcs1topkcs8(LIBSSH2_SESSION *session,
             const unsigned char **data8, unsigned int *datalen8,
             const unsigned char *data1, unsigned int datalen1)
{
    asn1Element *prvk;
    asn1Element *pkcs8;
    unsigned char *data;

    *data8 = NULL;
    *datalen8 = 0;
    if (datalen1 < 2)
        return -1;
    prvk = asn1_new_from_bytes(data1, datalen1);
    if (!prvk)
        return -1;
    pkcs8 = rsaprivatekeyinfo(prvk);
    asn1delete(prvk);
    if (!prvk) {
        asn1delete(pkcs8);
        pkcs8 = NULL;
    }
    if (!pkcs8)
        return -1;
    data = (unsigned char *) LIBSSH2_ALLOC(session, pkcs8->end - pkcs8->header);
    if (!data) {
        asn1delete(pkcs8);
        return -1;
    }
    *data8 = data;
    *datalen8 = pkcs8->end - pkcs8->header;
    memcpy((char *) data, (char *) pkcs8->header, *datalen8);
    asn1delete(pkcs8);
    return 0;
}

static int
rsapkcs1privkey(LIBSSH2_SESSION *session,
                const unsigned char *data, unsigned int datalen,
                const unsigned char *passphrase, void *loadkeydata)
{
    const unsigned char *data8;
    unsigned int datalen8;
    int ret;

    if (pkcs1topkcs8(session, &data8, &datalen8, data, datalen))
        return -1;
    ret = rsapkcs8privkey(session, data8, datalen8, passphrase, loadkeydata);
    LIBSSH2_FREE(session, (char *) data8);
    return ret;
}

static int
rsapkcs1pubkey(LIBSSH2_SESSION *session,
               const unsigned char *data, unsigned int datalen,
               const unsigned char *passphrase, void *loadkeydata)
{
    const unsigned char *data8;
    unsigned int datalen8;
    int ret;

    if (pkcs1topkcs8(session, &data8, &datalen8, data, datalen))
        return -1;
    ret = rsapkcs8pubkey(session, data8, datalen8, passphrase, loadkeydata);
    LIBSSH2_FREE(session, (char *) data8);
    return ret;
}

static int
try_pem_load(LIBSSH2_SESSION *session, FILE *fp,
             const unsigned char *passphrase,
             const char *header, const char *trailer,
             loadkeyproc proc, void *loadkeydata)
{
    unsigned char *data = NULL;
    unsigned int datalen = 0;
    int c;
    int ret;

    fseek(fp, 0L, SEEK_SET);
    for (;;) {
        ret = _libssh2_pem_parse(session, header, trailer,
                                 fp, &data, &datalen);

        if (!ret) {
            ret = (*proc)(session, data, datalen, passphrase, loadkeydata);
            if (!ret)
                return 0;
        }

        if (data) {
            LIBSSH2_FREE(session, data);
            data = NULL;
        }
        c = getc(fp);

        if (c == EOF)
            break;

        ungetc(c, fp);
    }

    return -1;
}

static int
load_rsa_private_file(LIBSSH2_SESSION *session, const char *filename,
                      unsigned const char *passphrase,
                      loadkeyproc proc1, loadkeyproc proc8, void *loadkeydata)
{
    FILE *fp = fopen(filename, fopenrmode);
    unsigned char *data = NULL;
    size_t datalen = 0;
    int ret;
    long filesize;

    if (!fp)
        return -1;

    ret = try_pem_load(session, fp, passphrase, beginencprivkeyhdr,
                       endencprivkeyhdr, proc8, loadkeydata);
    if (ret)
        ret = try_pem_load(session, fp, passphrase, beginprivkeyhdr,
                           endprivkeyhdr, proc8, loadkeydata);
    if (ret)
        ret = try_pem_load(session, fp, passphrase, beginrsaprivkeyhdr,
                           endrsaprivkeyhdr, proc1, loadkeydata);
    fclose(fp);

    if (ret) {
        /* Try DER encoding. */
        fp = fopen(filename, fopenrbmode);
        fseek(fp, 0L, SEEK_END);
        filesize = ftell(fp);

        if (filesize <= 32768) {        /* Limit to a reasonable size. */
            datalen = filesize;
            data = (unsigned char *) alloca(datalen);
            if (data) {
                fseek(fp, 0L, SEEK_SET);
                fread(data, datalen, 1, fp);
                ret = (*proc8)(session, data, datalen, passphrase,
                               loadkeydata);
                if (ret)
                    ret = (*proc1)(session, data, datalen, passphrase,
                                   loadkeydata);
            }
        }
        fclose(fp);
    }

    return ret;
}

int
_libssh2_rsa_new_private(libssh2_rsa_ctx **rsa, LIBSSH2_SESSION *session,
                         const char *filename, unsigned const char *passphrase)
{
    libssh2_rsa_ctx *ctx = libssh2_init_crypto_ctx(NULL);
    int ret;
    Qc3_Format_ALGD0400_T algd;
    Qus_EC_t errcode;

    if (!ctx)
        return -1;
    ret = load_rsa_private_file(session, filename, passphrase,
                                rsapkcs1privkey, rsapkcs8privkey, (void *) ctx);
    if (!ret) {
        /* Create the algorithm context. */
        algd.Public_Key_Alg = Qc3_RSA;
        algd.PKA_Block_Format = Qc3_PKCS1_01;
        memset(algd.Reserved, 0, sizeof algd.Reserved);
        algd.Signing_Hash_Alg = Qc3_SHA1;
        set_EC_length(errcode, sizeof errcode);
        Qc3CreateAlgorithmContext((char *) &algd, Qc3_Alg_Public_Key,
                                  ctx->hash.Alg_Context_Token, &errcode);
        if (errcode.Bytes_Available)
            ret = -1;
    }
    if (ret) {
        _libssh2_os400qc3_crypto_dtor(ctx);
        ctx = NULL;
    }
    *rsa = ctx;
    return ret;
}

int
_libssh2_pub_priv_keyfile(LIBSSH2_SESSION *session,
                          unsigned char **method, size_t *method_len,
                          unsigned char **pubkeydata, size_t *pubkeydata_len,
                          const char *privatekey, const char *passphrase)

{
    loadpubkeydata p;
    int ret;

    *method = NULL;
    *method_len = 0;
    *pubkeydata = NULL;
    *pubkeydata_len = 0;
    /* Note: passphrase not supported. */
    ret = load_rsa_private_file(session, privatekey, passphrase,
                                rsapkcs1pubkey, rsapkcs8pubkey, (void *) &p);
    if (!ret) {
        *method_len = strlen(p.method);
        if ((*method = LIBSSH2_ALLOC(session, *method_len)))
            memcpy((char *) *method, p.method, *method_len);
        else
            ret = -1;
    }

    if (ret) {
        if (*method)
            LIBSSH2_FREE(session, *method);
        if (p.data)
            LIBSSH2_FREE(session, (void *) p.data);
        *method = NULL;
        *method_len = 0;
    } else {
        *pubkeydata = (unsigned char *) p.data;
        *pubkeydata_len = p.length;
    }

    return ret;
}

int
_libssh2_rsa_new_private_frommemory(libssh2_rsa_ctx **rsa,
                                    LIBSSH2_SESSION *session,
                                    const char *filedata,
                                    size_t filedata_len,
                                    unsigned const char *passphrase)
{
    libssh2_rsa_ctx *ctx = libssh2_init_crypto_ctx(NULL);
    unsigned char *data = NULL;
    unsigned int datalen = 0;
    int ret;
    Qc3_Format_ALGD0400_T algd;
    Qus_EC_t errcode;

    if (!ctx)
        return -1;

    ret = _libssh2_pem_parse_memory(session,
                                    beginencprivkeyhdr, endencprivkeyhdr,
                                    filedata, filedata_len, &data, &datalen);
    if (ret)
        ret = _libssh2_pem_parse_memory(session,
                                        beginprivkeyhdr, endprivkeyhdr,
                                        filedata, filedata_len,
                                        &data, &datalen);
    if (!ret)
        ret = rsapkcs8privkey(session,
                              data, datalen, passphrase, (void *) &ctx);
    else {
        ret = _libssh2_pem_parse_memory(session,
                                        beginrsaprivkeyhdr, endrsaprivkeyhdr,
                                        filedata, filedata_len,
                                        &data, &datalen);
        if (!ret)
            ret = rsapkcs1privkey(session,
                                  data, datalen, passphrase, (void *) &ctx);
    }

    if (ret) {
        ret = rsapkcs8privkey(session, filedata, filedata_len,
                              passphrase, (void *) &ctx);
        if (ret)
            ret = rsapkcs1privkey(session, filedata, filedata_len,
                                  passphrase, (void *) &ctx);
    }

    if (data)
        LIBSSH2_FREE(session, data);

    if (!ret) {
        /* Create the algorithm context. */
        algd.Public_Key_Alg = Qc3_RSA;
        algd.PKA_Block_Format = Qc3_PKCS1_01;
        memset(algd.Reserved, 0, sizeof algd.Reserved);
        algd.Signing_Hash_Alg = Qc3_SHA1;
        set_EC_length(errcode, sizeof errcode);
        Qc3CreateAlgorithmContext((char *) &algd, Qc3_Alg_Public_Key,
                                  ctx->hash.Alg_Context_Token, &errcode);
        if (errcode.Bytes_Available)
            ret = -1;
    }

    if (ret) {
        _libssh2_os400qc3_crypto_dtor(ctx);
        ctx = NULL;
    }

    *rsa = ctx;
    return ret;
}

int
_libssh2_pub_priv_keyfilememory(LIBSSH2_SESSION *session,
                                unsigned char **method, size_t *method_len,
                                unsigned char **pubkeydata,
                                size_t *pubkeydata_len,
                                const char *privatekeydata,
                                size_t privatekeydata_len,
                                const char *passphrase)
{
    loadpubkeydata p;
    unsigned char *data = NULL;
    unsigned int datalen = 0;
    const char *meth;
    int ret;

    *method = NULL;
    *method_len = 0;
    *pubkeydata = NULL;
    *pubkeydata_len = 0;
    ret = _libssh2_pem_parse_memory(session,
                                    beginencprivkeyhdr, endencprivkeyhdr,
                                    privatekeydata, privatekeydata_len,
                                    &data, &datalen);
    if (ret)
        ret = _libssh2_pem_parse_memory(session,
                                        beginprivkeyhdr, endprivkeyhdr,
                                        privatekeydata, privatekeydata_len,
                                        &data, &datalen);
    if (!ret)
        ret = rsapkcs8pubkey(session,
                             data, datalen, passphrase, (void *) &p);
    else {
        ret = _libssh2_pem_parse_memory(session,
                                        beginrsaprivkeyhdr, endrsaprivkeyhdr,
                                        privatekeydata, privatekeydata_len,
                                        &data, &datalen);
        if (!ret)
            ret = rsapkcs1pubkey(session,
                                 data, datalen, passphrase, (void *) &p);
    }

    if (ret) {
        ret = rsapkcs8pubkey(session, privatekeydata, privatekeydata_len,
                             passphrase, (void *) &p);
        if (ret)
            ret = rsapkcs1pubkey(session, privatekeydata, privatekeydata_len,
                                 passphrase, (void *) &p);
    }

    if (data)
        LIBSSH2_FREE(session, data);

    if (!ret) {
        *method_len = strlen(p.method);
        if ((*method = LIBSSH2_ALLOC(session, *method_len)))
            memcpy((char *) *method, p.method, *method_len);
        else
            ret = -1;
    }
    if (ret) {
        if (*method)
            LIBSSH2_FREE(session, *method);
        if (p.data)
            LIBSSH2_FREE(session, (void *) p.data);
        *method = NULL;
        *method_len = 0;
    } else {
        *pubkeydata = (unsigned char *) p.data;
        *pubkeydata_len = p.length;
    }

    return ret;
}

int
_libssh2_rsa_sha1_verify(libssh2_rsa_ctx *rsa,
                         const unsigned char *sig, unsigned long sig_len,
                         const unsigned char *m, unsigned long m_len)
{
    Qus_EC_t errcode;
    int slen = sig_len;
    int mlen = m_len;

    set_EC_length(errcode, sizeof errcode);
    Qc3VerifySignature((char *) sig, &slen, (char *) m, &mlen, Qc3_Data,
                       rsa->hash.Alg_Context_Token, Qc3_Alg_Token,
                       rsa->key.Key_Context_Token, Qc3_Key_Token, anycsp,
                       NULL, (char *) &errcode);
    return errcode.Bytes_Available? -1: 0;
}

int
_libssh2_os400qc3_rsa_sha1_signv(LIBSSH2_SESSION *session,
                                 unsigned char **signature,
                                 size_t *signature_len,
                                 int veccount,
                                 const struct iovec vector[],
                                 libssh2_rsa_ctx *ctx)
{
    Qus_EC_t errcode;
    int siglen;
    unsigned char *sig;
    char sigbuf[8192];
    int sigbufsize = sizeof sigbuf;

    ctx->hash.Final_Op_Flag = Qc3_Final;
    set_EC_length(errcode, sizeof errcode);
    Qc3CalculateSignature((char *) vector, &veccount, Qc3_Array,
                          (char *) &ctx->hash, Qc3_Alg_Token,
                          (char *) &ctx->key, Qc3_Key_Token,
                          anycsp, NULL, sigbuf, &sigbufsize, &siglen,
                          (char *) &errcode);
    ctx->hash.Final_Op_Flag = Qc3_Continue;
    if (errcode.Bytes_Available)
        return -1;
    sig = LIBSSH2_ALLOC(session, siglen);
    if (!sig)
        return -1;
    memcpy((char *) sig, sigbuf, siglen);
    *signature = sig;
    *signature_len = siglen;
    return 0;
}

void
_libssh2_init_aes_ctr(void)
{
}

#endif /* LIBSSH2_OS400QC3 */

/* vim: set expandtab ts=4 sw=4: */
