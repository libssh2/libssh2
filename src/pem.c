/* Copyright (C) The Written Word, Inc.
 * Copyright (C) Simon Josefsson
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

static int pem_readline_file(char *line, int line_size, FILE *fp)
{
    size_t len;

    if(!line)
        return -1;
    if(!fgets(line, line_size, fp))
        return -1;

    if(*line) {
        len = strlen(line);
        if(len > 0 && line[len - 1] == '\n')
            line[len - 1] = '\0';
    }

    if(*line) {
        len = strlen(line);
        if(len > 0 && line[len - 1] == '\r')
            line[len - 1] = '\0';
    }

    return 0;
}

static int pem_readline_blob(char *line, size_t line_size,
                             const char *blob, size_t blob_len,
                             size_t *blob_offset)
{
    size_t off, len;

    off = *blob_offset;

    for(len = 0; off + len < blob_len && len < line_size - 1; len++) {
        if(blob[off + len] == '\n' ||
           blob[off + len] == '\r')
            break;
    }

    if(len) {
        memcpy(line, blob + off, len);
        *blob_offset += len;
    }

    line[len] = '\0';

    if(*blob_offset < blob_len && blob[*blob_offset] == '\r')
        *blob_offset += 1;
    if(*blob_offset < blob_len && blob[*blob_offset] == '\n')
        *blob_offset += 1;

    return *blob_offset > off ? 0 : -1;
}

#define LINE_SIZE 128

static const char *crypt_annotation = "Proc-Type: 4,ENCRYPTED";

static unsigned char pem_hex_decode(char digit)
{
    return (unsigned char)
        ((digit >= 'A') ? (0xA + (digit - 'A')) : (digit - '0'));
}

static int pem_FILE_to_blob(LIBSSH2_SESSION *session, FILE *fp,
                            char **blob, size_t *blob_len)
{
    int ret = -1;
    long file_size;
    char *filedata = NULL;
    size_t filedata_len = 0;

    if(fseek(fp, 0L, SEEK_END)) {
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE,
                       "Bad seek to file end in PEM parsing");
        goto out;
    }
    file_size = ftell(fp);
    if(file_size < 0) {
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE,
                       "Error determining size in PEM parsing");
        goto out;
    }
    if(file_size == 0) {
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE,
                       "Zero-length file in PEM parsing");
        goto out;
    }
    if(file_size > (1024 * 1024)) {
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE,
                       "Input too large in PEM parsing");
        goto out;
    }
    if(fseek(fp, 0L, SEEK_SET)) {
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE, "Bad seek to 0 in PEM parsing");
        goto out;
    }

    filedata_len = (size_t)file_size;
    filedata = SSH2_ALLOC(session, filedata_len);
    if(!filedata) {
        ret = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                       "Unable to allocate memory for PEM parsing");
        goto out;
    }

    if(fread(filedata, 1, filedata_len, fp) != filedata_len) {
        ret = ssh2_err(session, LIBSSH2_ERROR_FILE, "Bad read in PEM parsing");
        goto out;
    }

    ret = 0;

out:

    if(!ret) {
        *blob = filedata;
        *blob_len = filedata_len;
    }
    else if(filedata)
        SSH2_FREE(session, filedata);

    return ret;
}

int ssh2_pem_parse(LIBSSH2_SESSION *session,
                   const char *headerbegin,
                   const char *headerend,
                   FILE *fp,
                   const char *blob, size_t blob_len,
                   const char *passphrase,
                   unsigned char **data, size_t *datalen)
{
    char line[LINE_SIZE];
    unsigned char iv[LINE_SIZE];
    char *b64data = NULL;
    size_t b64datalen = 0;
    size_t off = 0;
    int ret = -1;
    const struct crypt_method *method = NULL;
    char *filedata = NULL;
    size_t filedata_len = 0;

    *data = NULL;
    *datalen = 0;

    if(fp) {
        ret = pem_FILE_to_blob(session, fp, &filedata, &filedata_len);
        if(ret)
            goto out;
        blob = filedata;
        blob_len = filedata_len;
    }

    do {
        *line = '\0';

        if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off))
            goto out;
    } while(strcmp(line, headerbegin));

    if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off))
        goto out;

    if(passphrase &&
       !memcmp(line, crypt_annotation, strlen(crypt_annotation))) {
        const struct crypt_method **all_methods, *cur_method;
        int i;

        if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off))
            goto out;

        all_methods = ssh2_crypt_methods();
        /* !checksrc! disable EQUALSNULL 1 */
        while((cur_method = *all_methods++) != NULL) {
            if(*cur_method->pem_annotation &&
               !memcmp(line, cur_method->pem_annotation,
                       strlen(cur_method->pem_annotation))) {
                method = cur_method;
                memcpy(iv, line + strlen(method->pem_annotation) + 1,
                       2 * method->iv_len);
            }
        }

        /* None of the available crypt methods were able to decrypt the key */
        if(!method) {
            ret = ssh2_err(session, LIBSSH2_ERROR_ALGO_UNSUPPORTED,
                           "Unable to decrypt PEM, unsupported algorithm");
            goto out;
        }

        /* Decode IV from hex */
        for(i = 0; i < method->iv_len; ++i) {
            iv[i] = (unsigned char)(pem_hex_decode(iv[2 * i]) << 4);
            iv[i] |= pem_hex_decode(iv[2 * i + 1]);
        }

        /* skip to the next line */
        if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off))
            goto out;
    }

    do {
        if(*line) {
            char *tmp;
            size_t linelen;

            linelen = strlen(line);
            tmp = SSH2_REALLOC(session, b64data, b64datalen + linelen);
            if(!tmp) {
                ret = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                               "Unable to allocate memory for PEM parsing");
                goto out;
            }
            memcpy(tmp + b64datalen, line, linelen);
            b64data = tmp;
            b64datalen += linelen;
        }

        *line = '\0';

        if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off))
            goto out;
    } while(strcmp(line, headerend));

    if(!b64data)
        goto out;

    if(ssh2_base64_decode(session, (char **)data, datalen,
                          b64data, b64datalen))
        goto out;

    if(*datalen == 0)
        goto out; /* Invalid decode */

    if(method) {
#if LIBSSH2_MD5_PEM
        /* Set up decryption */
        int free_iv = 0, free_secret = 0, len_decrypted = 0;
        size_t padding = 0;
        int blocksize = method->blocksize;
        void *abstract;
        unsigned char secret[2 * SSH2_MD5_DIG_LEN];
        ssh2_hash_ctx ctx;  /* fingerprint */
        int hok;

        /* Perform key derivation (PBKDF1/MD5) */
        hok = ssh2_hash_init(&ctx, SSH2_MD5_ALG);
        if(hok) {
            hok &= ssh2_hash_update(&ctx, passphrase, strlen(passphrase));
            hok &= ssh2_hash_update(&ctx, iv, 8);
            hok &= ssh2_hash_final(&ctx, secret, SSH2_MD5_DIG_LEN);
        }
        if(!hok)
            goto out;
        if(method->secret_len > SSH2_MD5_DIG_LEN) {
            hok = ssh2_hash_init(&ctx, SSH2_MD5_ALG);
            if(hok) {
                hok &= ssh2_hash_update(&ctx, secret, SSH2_MD5_DIG_LEN);
                hok &= ssh2_hash_update(&ctx, passphrase, strlen(passphrase));
                hok &= ssh2_hash_update(&ctx, iv, 8);
                hok &= ssh2_hash_final(&ctx, secret + SSH2_MD5_DIG_LEN,
                                       SSH2_MD5_DIG_LEN);
            }
            if(!hok)
                goto out;
        }

        /* Initialize the decryption */
        if(method->init(session, method, iv, &free_iv, secret, &free_secret, 0,
                        &abstract)) {
            ssh2_explicit_zero(secret, sizeof(secret));
            goto out;
        }

        if(free_secret)
            ssh2_explicit_zero(secret, sizeof(secret));

        /* Do the actual decryption */
        if((*datalen % blocksize) != 0) {
            ssh2_explicit_zero(secret, sizeof(secret));
            method->dtor(session, &abstract);
            goto out;
        }

        if(method->flags & SSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET) {
            if(method->crypt(session, 0, *data, *datalen, &abstract, 0)) {
                ret = LIBSSH2_ERROR_DECRYPT;
                ssh2_explicit_zero(secret, sizeof(secret));
                method->dtor(session, &abstract);
                goto out;
            }
        }
        else {
            while(len_decrypted <= (int)*datalen - blocksize) {
                if(method->crypt(session, 0, *data + len_decrypted, blocksize,
                                 &abstract,
                                 len_decrypted == 0
                                     ? FIRST_BLOCK
                                     : ((len_decrypted ==
                                         (int)*datalen - blocksize)
                                            ? LAST_BLOCK
                                            : MIDDLE_BLOCK))) {
                    ret = LIBSSH2_ERROR_DECRYPT;
                    ssh2_explicit_zero(secret, sizeof(secret));
                    method->dtor(session, &abstract);
                    goto out;
                }

                len_decrypted += blocksize;
            }
        }

        /* Account for padding */
        padding = (*data)[*datalen - 1];
        if(padding > *datalen) {
            ret = LIBSSH2_ERROR_DECRYPT;  /* Invalid padding len */
            goto out;
        }
        memset(&(*data)[*datalen - padding], 0, padding);
        *datalen -= padding;

        /* Clean up */
        ssh2_explicit_zero(secret, sizeof(secret));
        method->dtor(session, &abstract);
#else
        ssh2_err(session, LIBSSH2_ERROR_ALGO_UNSUPPORTED,
                 "Unable to decrypt PEM, MD5 not enabled");
        goto out;
#endif
    }

    ret = 0;

out:

    if(ret && *data) {
        ssh2_explicit_zero(*data, *datalen);
        SSH2_SAFEFREE(session, *data);
        *datalen = 0;
    }

    if(filedata)
        SSH2_FREE(session, filedata);

    if(b64data) {
        ssh2_explicit_zero(b64data, b64datalen);
        SSH2_FREE(session, b64data);
    }

    return ret;
}

/* OpenSSH formatted keys */

#define OPENSSH_PRIVKEY_HEADER     "-----BEGIN OPENSSH PRIVATE KEY-----"
#define OPENSSH_PRIVKEY_FOOTER     "-----END OPENSSH PRIVATE KEY-----"
#define OPENSSH_PRIVKEY_AUTH_MAGIC "openssh-key-v1"

static int pem_parse_data_openssh(LIBSSH2_SESSION *session,
                                  const char *passphrase,
                                  const char *b64data, size_t b64datalen,
                                  struct string_buf **decrypted_buf)
{
    const struct crypt_method *method = NULL;
    struct string_buf decoded, decrypted, kdf_buf;
    unsigned char *ciphername = NULL;
    unsigned char *kdfname = NULL;
    unsigned char *kdf = NULL;
    unsigned char *buf = NULL;
    unsigned char *salt = NULL;
    uint32_t nkeys, check1, check2;
    uint32_t rounds = 0;
    unsigned char *key = NULL;
    unsigned char *key_part = NULL;
    unsigned char *iv_part = NULL;
    unsigned char *f = NULL;
    size_t f_len = 0;
    int ret = 0, keylen = 0, ivlen = 0, total_len = 0;
    size_t kdf_len = 0, tmp_len = 0, salt_len = 0;

    if(decrypted_buf)
        *decrypted_buf = NULL;

    /* decode file */
    if(ssh2_base64_decode(session, (char **)&f, &f_len, b64data, b64datalen)) {
        ret = -1;
        goto out;
    }

    /* Parse the file */
    decoded.data = f;
    decoded.dataptr = f;
    decoded.len = f_len;

    if(decoded.len < sizeof(OPENSSH_PRIVKEY_AUTH_MAGIC)) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO, "key too short");
        goto out;
    }

    if(memcmp((const char *)decoded.dataptr, OPENSSH_PRIVKEY_AUTH_MAGIC,
              sizeof(OPENSSH_PRIVKEY_AUTH_MAGIC))) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                       "key auth magic mismatch");
        goto out;
    }

    decoded.dataptr += sizeof(OPENSSH_PRIVKEY_AUTH_MAGIC);

    if(ssh2_get_string(&decoded, &ciphername, &tmp_len) || tmp_len == 0) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO, "ciphername is missing");
        goto out;
    }

    if(ssh2_get_string(&decoded, &kdfname, &tmp_len) || tmp_len == 0) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO, "kdfname is missing");
        goto out;
    }

    if(ssh2_get_string(&decoded, &kdf, &kdf_len)) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO, "KDF is missing");
        goto out;
    }
    else {
        kdf_buf.data = kdf;
        kdf_buf.dataptr = kdf;
        kdf_buf.len = kdf_len;
    }

    if((!passphrase || strlen(passphrase) == 0) &&
       strcmp((const char *)ciphername, "none")) {
        /* passphrase required */
        ret = LIBSSH2_ERROR_KEYFILE_AUTH_FAILED;
        goto out;
    }

    if(strcmp((const char *)kdfname, "none") &&
       strcmp((const char *)kdfname, "bcrypt")) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                       "unrecognized KDF algorithm");
        goto out;
    }

    if(!strcmp((const char *)kdfname, "none") &&
       strcmp((const char *)ciphername, "none")) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO, "invalid format");
        goto out;
    }

    if(ssh2_get_u32(&decoded, &nkeys) != 0 || nkeys != 1) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                       "Multiple keys are unsupported");
        goto out;
    }

    /* unencrypted public key */

    if(ssh2_get_string(&decoded, &buf, &tmp_len) || tmp_len == 0) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                       "Invalid private key; expect embedded public key");
        goto out;
    }

    if(ssh2_get_string(&decoded, &buf, &tmp_len) || tmp_len == 0) {
        ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                       "Private key data not found");
        goto out;
    }

    /* decode encrypted private key */
    decrypted.data = decrypted.dataptr = buf;
    decrypted.len = tmp_len;

    if(ciphername && strcmp((const char *)ciphername, "none")) {
        const struct crypt_method **all_methods, *cur_method;

        all_methods = ssh2_crypt_methods();
        /* !checksrc! disable EQUALSNULL 1 */
        while((cur_method = *all_methods++) != NULL) {
            if(*cur_method->name && !memcmp(ciphername, cur_method->name,
                                            strlen(cur_method->name)))
                method = cur_method;
        }

        /* None of the available crypt methods were able to decrypt the key */

        if(!method) {
            ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                           "No supported cipher found");
            goto out;
        }
    }

    if(method) {
        int free_iv = 0, free_secret = 0, len_decrypted = 0;
        int blocksize;
        void *abstract = NULL;

        keylen = method->secret_len;
        ivlen = method->iv_len;
        total_len = keylen + ivlen;

        key = SSH2_CALLOC(session, total_len);
        if(!key) {
            ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                           "Could not alloc key");
            goto out;
        }

        if(!strcmp((const char *)kdfname, "bcrypt") && passphrase) {
            if(ssh2_get_string(&kdf_buf, &salt, &salt_len) ||
               ssh2_get_u32(&kdf_buf, &rounds) != 0) {
                ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                               "KDF contains unexpected values");
                goto out;
            }

            if(ssh2_bcrypt_pbkdf(passphrase, strlen(passphrase),
                                 salt, salt_len, key,
                                 keylen + ivlen, rounds) < 0) {
                ret = ssh2_err(session, LIBSSH2_ERROR_DECRYPT,
                               "invalid format");
                goto out;
            }
        }
        else {
            ret = ssh2_err(session, LIBSSH2_ERROR_KEYFILE_AUTH_FAILED,
                           "bcrypt-encrypted without passphrase");
            goto out;
        }

        /* Set up decryption */
        blocksize = method->blocksize;

        key_part = SSH2_CALLOC(session, keylen);
        if(!key_part) {
            ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                           "Could not alloc key part");
            goto out;
        }

        iv_part = SSH2_CALLOC(session, ivlen);
        if(!iv_part) {
            ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                           "Could not alloc iv part");
            goto out;
        }

        memcpy(key_part, key, keylen);
        memcpy(iv_part, key + keylen, ivlen);

        /* Initialize the decryption */
        if(method->init(session, method, iv_part, &free_iv, key_part,
                        &free_secret, 0, &abstract)) {
            ret = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }

        /* Do the actual decryption */
        if((decrypted.len % blocksize) != 0) {
            method->dtor(session, &abstract);
            ret = LIBSSH2_ERROR_DECRYPT;
            goto out;
        }

        if(method->flags & SSH2_CRYPT_FLAG_REQUIRES_FULL_PACKET) {
            if(method->crypt(session, 0, decrypted.data,
                             decrypted.len, &abstract, MIDDLE_BLOCK)) {
                ret = LIBSSH2_ERROR_DECRYPT;
                method->dtor(session, &abstract);
                goto out;
            }
        }
        else {
            while((size_t)len_decrypted <= decrypted.len - blocksize) {
                /* We always pass MIDDLE_BLOCK here because OpenSSH Key Files
                 * do not use AAD to authenticate the length.
                 * Furthermore, the authentication tag is appended after the
                 * encrypted key, and the length of the authentication tag is
                 * not included in the key length, so we check it after the
                 * loop.
                 */
                if(method->crypt(session, 0, decrypted.data + len_decrypted,
                                 blocksize, &abstract, MIDDLE_BLOCK)) {
                    ret = LIBSSH2_ERROR_DECRYPT;
                    method->dtor(session, &abstract);
                    goto out;
                }

                len_decrypted += blocksize;
            }

            /* No padding */

            /* for the AES-GCM methods, the 16-byte authentication tag is
             * appended to the encrypted key */
            if(!strcmp(method->name, "aes256-gcm@openssh.com") ||
               !strcmp(method->name, "aes128-gcm@openssh.com")) {
                if(!ssh2_check_length(&decoded, 16)) {
                    ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                                   "GCM auth tag missing");
                    method->dtor(session, &abstract);
                    goto out;
                }
                if(method->crypt(session, 0, decoded.dataptr,
                                 16, &abstract, LAST_BLOCK)) {
                    ret = ssh2_err(session, LIBSSH2_ERROR_DECRYPT,
                                   "GCM auth tag invalid");
                    method->dtor(session, &abstract);
                    goto out;
                }
                decoded.dataptr += 16;
            }
        }

        method->dtor(session, &abstract);
    }

    /* Check random bytes match */

    if(ssh2_get_u32(&decrypted, &check1) != 0 ||
       ssh2_get_u32(&decrypted, &check2) != 0 ||
       check1 != check2) {
        ssh2_err(session, LIBSSH2_ERROR_PROTO,
                 "Private key unpack failed (correct password?)");
        ret = LIBSSH2_ERROR_KEYFILE_AUTH_FAILED;
        goto out;
    }

    if(decrypted_buf) {
        /* copy data to out-going buffer */
        struct string_buf *out_buf = ssh2_string_buf_new(session);
        if(!out_buf) {
            ret = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                           "Unable to allocate memory for decrypted struct");
            goto out;
        }

        out_buf->data = SSH2_CALLOC(session, decrypted.len);
        if(!out_buf->data) {
            ret = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                           "Unable to allocate memory for decrypted struct");
            ssh2_string_buf_free(session, out_buf);
            goto out;
        }
        memcpy(out_buf->data, decrypted.data, decrypted.len);
        out_buf->dataptr = out_buf->data +
            (decrypted.dataptr - decrypted.data);
        out_buf->len = decrypted.len;

        *decrypted_buf = out_buf;
    }

out:

    /* Clean up */
    if(key) {
        ssh2_explicit_zero(key, total_len);
        SSH2_FREE(session, key);
    }
    if(key_part) {
        ssh2_explicit_zero(key_part, keylen);
        SSH2_FREE(session, key_part);
    }
    if(iv_part) {
        ssh2_explicit_zero(iv_part, ivlen);
        SSH2_FREE(session, iv_part);
    }
    if(f) {
        ssh2_explicit_zero(f, f_len);
        SSH2_FREE(session, f);
    }

    return ret;
}

int ssh2_openssh_pem_parse_FILE(LIBSSH2_SESSION *session,
                                FILE *fp,
                                const char *passphrase,
                                struct string_buf **decrypted_buf)
{
    char line[LINE_SIZE];
    char *b64data = NULL;
    size_t b64datalen = 0;
    int ret = 0;

    /* read file */

    do {
        *line = '\0';

        if(pem_readline_file(line, LINE_SIZE, fp))
            return -1;
    } while(strcmp(line, OPENSSH_PRIVKEY_HEADER));

    if(pem_readline_file(line, LINE_SIZE, fp))
        return -1;

    do {
        if(*line) {
            char *tmp;
            size_t linelen;

            linelen = strlen(line);
            tmp = SSH2_REALLOC(session, b64data, b64datalen + linelen);
            if(!tmp) {
                ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                         "Unable to allocate memory for PEM parsing");
                ret = -1;
                goto out;
            }
            memcpy(tmp + b64datalen, line, linelen);
            b64data = tmp;
            b64datalen += linelen;
        }

        *line = '\0';

        if(pem_readline_file(line, LINE_SIZE, fp)) {
            ret = -1;
            goto out;
        }
    } while(strcmp(line, OPENSSH_PRIVKEY_FOOTER));

    if(!b64data)
        return -1;

    ret = pem_parse_data_openssh(session, passphrase,
                                 b64data, b64datalen, decrypted_buf);

    if(b64data) {
        ssh2_explicit_zero(b64data, b64datalen);
        SSH2_FREE(session, b64data);
    }

out:

    return ret;
}

int ssh2_openssh_pem_parse_blob(LIBSSH2_SESSION *session,
                                const char *blob, size_t blob_len,
                                const char *passphrase,
                                struct string_buf **decrypted_buf)
{
    char line[LINE_SIZE];
    char *b64data = NULL;
    size_t b64datalen = 0;
    size_t off = 0;
    int ret;

    if(!blob || blob_len == 0)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "Error parsing PEM: blob missing");

    do {

        *line = '\0';

        if(off >= blob_len)
            return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                            "Error parsing PEM: OpenSSH header not found");

        if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off))
            return -1;
    } while(strcmp(line, OPENSSH_PRIVKEY_HEADER));

    *line = '\0';

    do {
        if(*line) {
            char *tmp;
            size_t linelen;

            linelen = strlen(line);
            tmp = SSH2_REALLOC(session, b64data, b64datalen + linelen);
            if(!tmp) {
                ret = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                               "Unable to allocate memory for PEM parsing");
                goto out;
            }
            memcpy(tmp + b64datalen, line, linelen);
            b64data = tmp;
            b64datalen += linelen;
        }

        *line = '\0';

        if(off >= blob_len) {
            ret = ssh2_err(session, LIBSSH2_ERROR_PROTO,
                           "Error parsing PEM: offset out of bounds");
            goto out;
        }

        if(pem_readline_blob(line, LINE_SIZE, blob, blob_len, &off)) {
            ret = -1;
            goto out;
        }
    } while(strcmp(line, OPENSSH_PRIVKEY_FOOTER));

    if(!b64data)
        return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                        "Error parsing PEM: base 64 data missing");

    ret = pem_parse_data_openssh(session, passphrase,
                                 b64data, b64datalen, decrypted_buf);

out:
    if(b64data) {
        ssh2_explicit_zero(b64data, b64datalen);
        SSH2_FREE(session, b64data);
    }
    return ret;
}

static int pem_read_asn1_length(const unsigned char *data,
                                size_t datalen, size_t *len)
{
    unsigned int lenlen;
    int nextpos;

    if(datalen < 1)
        return -1;
    *len = data[0];

    if(*len >= 0x80) {
        lenlen = *len & 0x7F;
        if(1 + lenlen > datalen)
            return -1;
        *len = data[1];
        if(lenlen > 1) {
            *len <<= 8;
            if(2 + lenlen > datalen)
                return -1;
            *len |= data[2];
        }
    }
    else
        lenlen = 0;

    nextpos = 1 + lenlen;
    if(lenlen > 2 || 1 + lenlen + *len > datalen)
        return -1;

    return nextpos;
}

int ssh2_pem_decode_sequence(unsigned char **data, size_t *datalen)
{
    size_t len;
    int lenlen;

    if(*datalen < 1)
        return -1;

    if((*data)[0] != '\x30')
        return -1;

    (*data)++;
    (*datalen)--;

    lenlen = pem_read_asn1_length(*data, *datalen, &len);
    if(lenlen < 0 || lenlen + len != *datalen)
        return -1;

    *data += lenlen;
    *datalen -= lenlen;

    return 0;
}

int ssh2_pem_decode_integer(unsigned char **data, size_t *datalen,
                            unsigned char **i, unsigned int *ilen)
{
    size_t len;
    int lenlen;

    if(*datalen < 1)
        return -1;

    if((*data)[0] != '\x02')
        return -1;

    (*data)++;
    (*datalen)--;

    lenlen = pem_read_asn1_length(*data, *datalen, &len);
    if(lenlen < 0 || lenlen + len > *datalen)
        return -1;

    *data += lenlen;
    *datalen -= lenlen;

    *i = *data;
    *ilen = (unsigned int)len;

    *data += len;
    *datalen -= len;

    return 0;
}
