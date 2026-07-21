/* Copyright (C) Sara Golemon <sarag@libssh2.org>
 * Copyright (C) Mikhail Gusarov <dottedmag@dottedmag.net>
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

#include <ctype.h>

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "transport.h"
#include "session.h"
#include "userauth.h"
#include "userauth_kbd_packet.h"

#include <stdlib.h>  /* strtol() */

/*
 * Cap each userauth input field below the per-call transport
 * limit. Bounds packet-size arithmetic to prevent size_t wrap
 * and undersized allocations on 32-bit (or any) platforms.
 * Packets with multiple near-cap fields may still exceed the
 * transport limit and be rejected later with
 * LIBSSH2_ERROR_OUT_OF_BOUNDARY.
 */
#define MAX_INPUT_LEN (MAX_SSH_PACKET_LEN - 0x100)

/*
 * List authentication methods
 * Yields successful login if "none" happens to be allowable for this user
 * Not a common configuration for any SSH server though
 * username should be NULL, or a null-terminated string
 */
static char *userauth_list(LIBSSH2_SESSION *session, const char *username,
                           unsigned int username_len)
{
    unsigned char reply_codes[4] = {
        SSH_MSG_USERAUTH_SUCCESS,
        SSH_MSG_USERAUTH_FAILURE,
        SSH_MSG_USERAUTH_BANNER,
        0
    };
    /* packet_type(1) + username_len(4) + service_len(4) +
       service(14)"ssh-connection" + method_len(4) = 27 */
    unsigned long methods_len;
    unsigned int banner_len;
    unsigned char *s;
    int rc;

    if(session->userauth_list_state == ssh2_NB_state_idle) {
        size_t data_len;

        /* Zero the whole thing out */
        memset(&session->userauth_list_packet_requirev_state, 0,
               sizeof(session->userauth_list_packet_requirev_state));

        if(username_len > MAX_INPUT_LEN) {
            ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                     "Username length out of bounds");
            return NULL;
        }

        if(session->userauth_list_data)
            SSH2_FREE(session, session->userauth_list_data);

        data_len = username_len + 27;

        session->userauth_list_data_len = 0;
        session->userauth_list_data = s = SSH2_ALLOC(session, data_len);
        if(!session->userauth_list_data) {
            ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                     "Unable to allocate memory for userauth_list");
            return NULL;
        }
        session->userauth_list_data_len = data_len;

        *(s++) = SSH_MSG_USERAUTH_REQUEST;
        ssh2_store_str(&s, username, username_len);
        ssh2_store_str(&s, "ssh-connection", 14);
        ssh2_store_u32(&s, 4); /* send "none" separately */

        session->userauth_list_state = ssh2_NB_state_created;
    }

    if(session->userauth_list_state == ssh2_NB_state_created) {
        rc = ssh2_transport_send(session, session->userauth_list_data,
                                 session->userauth_list_data_len,
                                 (const unsigned char *)"none", 4);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
            ssh2_err(session, LIBSSH2_ERROR_EAGAIN,
                     "Would block requesting userauth list");
            return NULL;
        }
        /* now free the packet that was sent */
        SSH2_SAFEFREE(session, session->userauth_list_data);

        if(rc) {
            ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                     "Unable to send userauth-none request");
            session->userauth_list_state = ssh2_NB_state_idle;
            return NULL;
        }

        session->userauth_list_state = ssh2_NB_state_sent;
    }

    if(session->userauth_list_state == ssh2_NB_state_sent) {
        rc = ssh2_packet_requirev(session, reply_codes,
                                  &session->userauth_list_data,
                                  &session->userauth_list_data_len, 0,
                                  NULL, 0,
                                &session->userauth_list_packet_requirev_state);
        if(rc == LIBSSH2_ERROR_EAGAIN) {
            ssh2_err(session, LIBSSH2_ERROR_EAGAIN,
                     "Would block requesting userauth list");
            return NULL;
        }
        else if(rc || session->userauth_list_data_len < 1) {
            ssh2_err(session, rc, "Failed getting response");
            session->userauth_list_state = ssh2_NB_state_idle;
            return NULL;
        }

        if(session->userauth_list_data[0] == SSH_MSG_USERAUTH_BANNER) {
            if(session->userauth_list_data_len < 5) {
                SSH2_SAFEFREE(session, session->userauth_list_data);
                ssh2_err(session, LIBSSH2_ERROR_PROTO,
                         "Unexpected packet size");
                return NULL;
            }
            banner_len = ssh2_ntohu32(session->userauth_list_data + 1);
            if(banner_len > session->userauth_list_data_len - 5) {
                SSH2_SAFEFREE(session, session->userauth_list_data);
                ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                         "Unexpected userauth banner size");
                return NULL;
            }

            if(session->userauth_banner)
                SSH2_FREE(session, session->userauth_banner);

            session->userauth_banner = SSH2_ALLOC(session, banner_len + 1);
            if(!session->userauth_banner) {
                SSH2_SAFEFREE(session, session->userauth_list_data);
                ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                         "Unable to allocate memory for userauth banner");
                return NULL;
            }
            memcpy(session->userauth_banner, session->userauth_list_data + 5,
                   banner_len);
            session->userauth_banner[banner_len] = '\0';
            ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Banner: %s",
                      session->userauth_banner));
            SSH2_SAFEFREE(session, session->userauth_list_data);
            /* SSH_MSG_USERAUTH_BANNER has been handled */
            reply_codes[2] = 0;
            rc = ssh2_packet_requirev(session, reply_codes,
                                      &session->userauth_list_data,
                                      &session->userauth_list_data_len, 0,
                                      NULL, 0,
                                &session->userauth_list_packet_requirev_state);
            if(rc == LIBSSH2_ERROR_EAGAIN) {
                ssh2_err(session, LIBSSH2_ERROR_EAGAIN,
                         "Would block requesting userauth list");
                return NULL;
            }
            else if(rc || session->userauth_list_data_len < 1) {
                ssh2_err(session, rc, "Failed getting response");
                session->userauth_list_state = ssh2_NB_state_idle;
                return NULL;
            }
        }

        if(session->userauth_list_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
            /* Wow, who'dve thought... */
            ssh2_err(session, LIBSSH2_ERROR_NONE, "No error");
            SSH2_SAFEFREE(session, session->userauth_list_data);
            session->state |= SSH2_STATE_AUTHENTICATED;
            session->userauth_list_state = ssh2_NB_state_idle;
            return NULL;
        }

        if(session->userauth_list_data_len < 5) {
            SSH2_SAFEFREE(session, session->userauth_list_data);
            ssh2_err(session, LIBSSH2_ERROR_PROTO, "Unexpected packet size");
            return NULL;
        }

        methods_len = ssh2_ntohu32(session->userauth_list_data + 1);
        if(methods_len >= session->userauth_list_data_len - 5) {
            ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                     "Unexpected userauth list size");
            return NULL;
        }

        /* Do note that the memory areas overlap! */
        memmove(session->userauth_list_data, session->userauth_list_data + 5,
                methods_len);
        session->userauth_list_data[methods_len] = '\0';
        ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Permitted auth methods: %s",
                  session->userauth_list_data));
    }

    session->userauth_list_state = ssh2_NB_state_idle;
    return (char *)session->userauth_list_data;
}

/*
 * List authentication methods
 * Yields successful login if "none" happens to be allowable for this user
 * Not a common configuration for any SSH server though
 * username should be NULL, or a null-terminated string
 */
char *libssh2_userauth_list(LIBSSH2_SESSION *session,
                            const char *username, unsigned int username_len)
{
    char *ptr;

    if(!session)
        return NULL;

    BLOCK_ADJUST_ERRNO(ptr, session,
                       userauth_list(session, username, username_len));
    return ptr;
}

/*
 * Retrieve banner message from server, if available.
 * When no such message is sent by server or if no authentication attempt has
 * been made, this function returns LIBSSH2_ERROR_MISSING_USERAUTH_BANNER.
 */
int libssh2_userauth_banner(LIBSSH2_SESSION *session, char **banner)
{
    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    if(!session->userauth_banner)
        return ssh2_err(session, LIBSSH2_ERROR_MISSING_USERAUTH_BANNER,
                        "Missing userauth banner");

    if(banner)
        *banner = session->userauth_banner;

    return LIBSSH2_ERROR_NONE;
}

/*
 * Returns: 0 if not yet authenticated
 *          1 if already authenticated
 */
int libssh2_userauth_authenticated(LIBSSH2_SESSION *session)
{
    if(!session)
        return 0;

    return (session->state & SSH2_STATE_AUTHENTICATED) ? 1 : 0;
}

/*
 * Plain old login
 */
static int userauth_password(LIBSSH2_SESSION *session,
                             const char *username,
                             unsigned int username_len,
                             const char *password,
                             unsigned int password_len,
                             LIBSSH2_PASSWD_CHANGEREQ_FUNC(*passwd_change_cb))
{
    static const unsigned char reply_codes[4] = {
        SSH_MSG_USERAUTH_SUCCESS,
        SSH_MSG_USERAUTH_FAILURE,
        SSH_MSG_USERAUTH_PASSWD_CHANGEREQ,
        0
    };

    int rc;
    unsigned char *s;
    size_t data_len;

    if(session->userauth_pswd_state == ssh2_NB_state_idle) {
        /* Zero the whole thing out */
        memset(&session->userauth_pswd_packet_requirev_state, 0,
               sizeof(session->userauth_pswd_packet_requirev_state));

        /* 40 = packet_type(1) + username_len(4) + service_len(4) +
           service(14)"ssh-connection" + method_len(4) + method(8)"password" +
           chgpwdbool(1) + password_len(4) */
        if(username_len > MAX_INPUT_LEN)
            return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                            "Username length out of bounds");
        if(password_len > MAX_INPUT_LEN)
            return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                            "Password length out of bounds");

        data_len = username_len + 40;

        session->userauth_pswd_data0 =
            (unsigned char)~SSH_MSG_USERAUTH_PASSWD_CHANGEREQ;

        /* TODO: remove this alloc with a fixed buffer in the session
           struct */
        session->userauth_pswd_data_len = 0;
        session->userauth_pswd_data = s = SSH2_ALLOC(session, data_len);
        if(!session->userauth_pswd_data)
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for "
                            "userauth-password request");
        session->userauth_pswd_data_len = data_len;

        *(s++) = SSH_MSG_USERAUTH_REQUEST;
        ssh2_store_str(&s, username, username_len);
        ssh2_store_str(&s, "ssh-connection", sizeof("ssh-connection") - 1);
        ssh2_store_str(&s, "password", sizeof("password") - 1);
        *s++ = '\0';
        ssh2_store_u32(&s, password_len);
        /* 'password' is sent separately */

        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Attempting to login using password authentication"));

        session->userauth_pswd_state = ssh2_NB_state_created;
    }

    if(session->userauth_pswd_state == ssh2_NB_state_created) {
        rc = ssh2_transport_send(session, session->userauth_pswd_data,
                                 session->userauth_pswd_data_len,
                                 (const unsigned char *)password,
                                 password_len);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN,
                            "Would block writing password request");

        /* now free the sent packet */
        SSH2_SAFEFREE(session, session->userauth_pswd_data);

        if(rc) {
            session->userauth_pswd_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                            "Unable to send userauth-password request");
        }

        session->userauth_pswd_state = ssh2_NB_state_sent;
    }

password_response:

    if(session->userauth_pswd_state == ssh2_NB_state_sent ||
       session->userauth_pswd_state == ssh2_NB_state_sent1 ||
       session->userauth_pswd_state == ssh2_NB_state_sent2) {
        if(session->userauth_pswd_state == ssh2_NB_state_sent) {
            rc = ssh2_packet_requirev(session, reply_codes,
                                      &session->userauth_pswd_data,
                                      &session->userauth_pswd_data_len,
                                      0, NULL, 0,
                                      &session->
                                      userauth_pswd_packet_requirev_state);

            if(rc) {
                if(rc != LIBSSH2_ERROR_EAGAIN)
                    session->userauth_pswd_state = ssh2_NB_state_idle;

                return ssh2_err(session, rc, "Waiting for password response");
            }
            else if(session->userauth_pswd_data_len < 1) {
                session->userauth_pswd_state = ssh2_NB_state_idle;
                return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                                "Unexpected packet size");
            }

            if(session->userauth_pswd_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
                ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                          "Password authentication successful"));
                SSH2_SAFEFREE(session, session->userauth_pswd_data);
                session->state |= SSH2_STATE_AUTHENTICATED;
                session->userauth_pswd_state = ssh2_NB_state_idle;
                return 0;
            }
            else if(session->userauth_pswd_data[0] ==
                    SSH_MSG_USERAUTH_FAILURE) {
                ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                          "Password authentication failed"));
                SSH2_SAFEFREE(session, session->userauth_pswd_data);
                session->userauth_pswd_state = ssh2_NB_state_idle;
                return ssh2_err(session, LIBSSH2_ERROR_AUTHENTICATION_FAILED,
                                "Authentication failed (username/password)");
            }

            session->userauth_pswd_newpw = NULL;
            session->userauth_pswd_newpw_len = 0;

            session->userauth_pswd_state = ssh2_NB_state_sent1;
        }

        if(session->userauth_pswd_data_len < 1) {
            session->userauth_pswd_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                            "Unexpected packet size");
        }

        if(session->userauth_pswd_data[0] ==
           SSH_MSG_USERAUTH_PASSWD_CHANGEREQ ||
           session->userauth_pswd_data0 ==
           SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
            session->userauth_pswd_data0 = SSH_MSG_USERAUTH_PASSWD_CHANGEREQ;

            if(session->userauth_pswd_state == ssh2_NB_state_sent1 ||
               session->userauth_pswd_state == ssh2_NB_state_sent2) {
                if(session->userauth_pswd_state == ssh2_NB_state_sent1) {
                    ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                              "Password change required"));
                    SSH2_SAFEFREE(session, session->userauth_pswd_data);
                }
                if(passwd_change_cb) {
                    if(session->userauth_pswd_state == ssh2_NB_state_sent1) {
                        passwd_change_cb(session,
                                         &session->userauth_pswd_newpw,
                                         &session->userauth_pswd_newpw_len,
                                         &session->abstract);
                        if(!session->userauth_pswd_newpw) {
                            session->userauth_pswd_state = ssh2_NB_state_idle;
                            session->userauth_pswd_data_len = 0;
                            return ssh2_err(session,
                                            LIBSSH2_ERROR_PASSWORD_EXPIRED,
                                            "Password expired, and "
                                            "callback failed");
                        }

                        session->userauth_pswd_data_len = 0;
                        if(username_len > MAX_INPUT_LEN ||
                           password_len > MAX_INPUT_LEN) {
                            session->userauth_pswd_state = ssh2_NB_state_idle;
                            SSH2_SAFEFREE(session,
                                          session->userauth_pswd_newpw);
                            return ssh2_err(session,
                                            LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                                            "Username or password too large");
                        }

                        /* basic data_len + newpw_len(4) */
                        data_len = username_len + password_len + 44;
                        session->userauth_pswd_data_len = 0;
                        session->userauth_pswd_data = s =
                            SSH2_ALLOC(session, data_len);
                        if(!session->userauth_pswd_data) {
                            session->userauth_pswd_state = ssh2_NB_state_idle;
                            SSH2_SAFEFREE(session,
                                          session->userauth_pswd_newpw);
                            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                                            "Unable to allocate memory "
                                            "for userauth password "
                                            "change request");
                        }
                        session->userauth_pswd_data_len = data_len;

                        *(s++) = SSH_MSG_USERAUTH_REQUEST;
                        ssh2_store_str(&s, username, username_len);
                        ssh2_store_str(&s, "ssh-connection",
                                       sizeof("ssh-connection") - 1);
                        ssh2_store_str(&s, "password", sizeof("password") - 1);
                        *s++ = 0x01;
                        ssh2_store_str(&s, password, password_len);
                        ssh2_store_u32(&s, session->userauth_pswd_newpw_len);
                        /* send session->userauth_pswd_newpw separately */

                        session->userauth_pswd_state = ssh2_NB_state_sent2;
                    }

                    if(session->userauth_pswd_state == ssh2_NB_state_sent2) {
                        rc = ssh2_transport_send(session,
                                            session->userauth_pswd_data,
                                            session->userauth_pswd_data_len,
                                            (const unsigned char *)
                                            session->userauth_pswd_newpw,
                                            session->userauth_pswd_newpw_len);
                        if(rc == LIBSSH2_ERROR_EAGAIN)
                            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN,
                                            "Would block waiting");

                        /* free the allocated packets again */
                        SSH2_SAFEFREE(session, session->userauth_pswd_data);
                        SSH2_SAFEFREE(session, session->userauth_pswd_newpw);

                        if(rc)
                            return ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                                            "Unable to send userauth "
                                            "password-change request");

                        /*
                         * Ugliest use of goto ever.  Blame it on the
                         * askN => requirev migration.
                         */
                        session->userauth_pswd_state = ssh2_NB_state_sent;
                        goto password_response;
                    }
                }
            }
            else {
                session->userauth_pswd_state = ssh2_NB_state_idle;
                return ssh2_err(session, LIBSSH2_ERROR_PASSWORD_EXPIRED,
                                "Password Expired, and no callback specified");
            }
        }
    }

    /* FAILURE */
    SSH2_SAFEFREE(session, session->userauth_pswd_data);
    session->userauth_pswd_state = ssh2_NB_state_idle;

    return ssh2_err(session, LIBSSH2_ERROR_AUTHENTICATION_FAILED,
                    "Authentication failed");
}

/*
 * Plain old login
 */
int libssh2_userauth_password_ex(
    LIBSSH2_SESSION *session,
    const char *username, unsigned int username_len,
    const char *password, unsigned int password_len,
    LIBSSH2_PASSWD_CHANGEREQ_FUNC(*passwd_change_cb))
{
    int rc;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    BLOCK_ADJUST(rc, session,
                 userauth_password(session, username, username_len,
                                   password, password_len,
                                   passwd_change_cb));
    return rc;
}

/*
 * Read a public key from an id_???.pub style file or blob
 *
 * Returns an allocated string containing the decoded key in *pubkeydata
 * on success.
 * Returns an allocated string containing the key method (e.g. "ssh-dss")
 * in method on success.
 */
static int userauth_read_pubkey(
    LIBSSH2_SESSION *session,
    char **method, size_t *method_len,
    unsigned char **pubkeydata, size_t *pubkeydata_len,
    const char *pubkeyfile,
    const char *pubkeyblob, size_t pubkeyblob_len)
{
    unsigned char *pubkey = NULL, *sp1, *sp2, *tmp;
    size_t pubkey_len;
    size_t sp_len, tmp_len;

    if(pubkeyfile) {
        FILE *fd;
        char c;

        pubkey_len = 0;

        ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Loading public key file: %s",
                  pubkeyfile));
        /* Read Public Key */
        fd = ssh2_fopen(pubkeyfile, "rb");
        if(!fd)
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Unable to open public key file");

        while(!feof(fd) && fread(&c, 1, 1, fd) == 1 && c != '\r' && c != '\n')
            pubkey_len++;

        fseek(fd, 0L, SEEK_SET);

        if(pubkey_len <= 1) {
            fclose(fd);
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Invalid data in public key file");
        }

        pubkey = SSH2_ALLOC(session, pubkey_len);
        if(!pubkey) {
            fclose(fd);
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for public key data");
        }
        if(fread(pubkey, 1, pubkey_len, fd) != pubkey_len) {
            SSH2_FREE(session, pubkey);
            fclose(fd);
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Unable to read public key from file");
        }
        fclose(fd);
    }
    else {
        if(!pubkeyblob || pubkeyblob_len <= 1)
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Invalid/missing data in public key blob");

        pubkey_len = pubkeyblob_len;

        pubkey = SSH2_ALLOC(session, pubkey_len);
        if(!pubkey)
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for public key data");

        memcpy(pubkey, pubkeyblob, pubkey_len);
    }

    /*
     * Remove trailing whitespace
     */
    while(pubkey_len && isspace(pubkey[pubkey_len - 1]))
        pubkey_len--;

    if(!pubkey_len) {
        SSH2_FREE(session, pubkey);
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Missing public key data");
    }

    sp1 = memchr(pubkey, ' ', pubkey_len);
    if(!sp1) {
        SSH2_FREE(session, pubkey);
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Invalid public key data");
    }

    sp1++;

    sp_len = sp1 > pubkey ? (sp1 - pubkey) : 0;
    sp2 = memchr(sp1, ' ', pubkey_len - sp_len);
    if(!sp2)
        /* Assume that the id string is missing, but that it is okay */
        sp2 = pubkey + pubkey_len;

    if(ssh2_base64_decode(session, (char **)&tmp, &tmp_len, (const char *)sp1,
                          sp2 - sp1)) {
        SSH2_FREE(session, pubkey);
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Invalid key data, not base64 encoded");
    }

    /* Wasting some bytes here (okay, more than some), but since it is likely
       to be freed soon anyway, we avoid the extra free/alloc and call
       it a wash */
    *method = (char *)pubkey;
    *method_len = sp1 - pubkey - 1;
    method[*method_len] = 0;

    *pubkeydata = tmp;
    *pubkeydata_len = tmp_len;

    return 0;
}

/*
 * Read a PEM encoded private key from an id_??? style file or blob
 */
static int userauth_read_privkey(
    LIBSSH2_SESSION *session,
    const struct hostkey_method **hostkey_method, void **hostkey_abstract,
    const char *method, size_t method_len,
    const char *privkeyfile,
    const char *privkeyblob, size_t privkeyblob_len,
    const char *passphrase)
{
    const struct hostkey_method **hostkey_methods_avail =
        ssh2_hostkey_methods();

    *hostkey_method = NULL;
    *hostkey_abstract = NULL;

    if(privkeyfile)
        ssh2_deb((session, LIBSSH2_TRACE_AUTH, "Loading private key file: %s",
                  privkeyfile));
    else if(!privkeyblob || !privkeyblob_len)
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Missing private key blob");

    while(*hostkey_methods_avail && (*hostkey_methods_avail)->name) {
        if((*hostkey_methods_avail)->initPEM &&
           !strncmp((*hostkey_methods_avail)->name, method, method_len)) {
            *hostkey_method = *hostkey_methods_avail;
            break;
        }
        hostkey_methods_avail++;
    }
    if(!*hostkey_method)
        return ssh2_err(session, LIBSSH2_ERROR_METHOD_NONE,
                        "No handler for specified private key");

    if((*hostkey_method)->initPEM(session,
                                  privkeyfile,
                                  privkeyblob, privkeyblob_len,
                                  passphrase, hostkey_abstract))
        return ssh2_err(session, LIBSSH2_ERROR_FILE, privkeyfile
                        ? "Unable to initialize private key from file"
                        : "Unable to initialize private key from memory");

    return 0;
}

struct privkey_info {
    const char *filename;
    const char *data;
    size_t data_len;
    const char *passphrase;
};

static int userauth_sign(LIBSSH2_SESSION *session,
                         unsigned char **sig, size_t *sig_len,
                         const unsigned char *data, size_t data_len,
                         void **abstract)
{
    struct privkey_info *pk_info = (struct privkey_info *)(*abstract);
    const struct hostkey_method *privkeyobj;
    void *hostkey_abstract;
    struct iovec datavec;
    int rc;

    rc = userauth_read_privkey(session, &privkeyobj, &hostkey_abstract,
                               session->userauth_pblc_method,
                               session->userauth_pblc_method_len,
                               pk_info->filename,
                               pk_info->data, pk_info->data_len,
                               pk_info->passphrase);
    if(rc)
        return rc;

    if(!privkeyobj)
        return -1;

    ssh2_prepare_iovec(&datavec, 1);
    datavec.iov_base = SSH2_UNCONST(data);
    datavec.iov_len = data_len;

    if(privkeyobj->signv(session, sig, sig_len, 1, &datavec,
                         &hostkey_abstract)) {
        if(privkeyobj->dtor)
            privkeyobj->dtor(session, &hostkey_abstract);
        return -1;
    }

    if(privkeyobj->dtor)
        privkeyobj->dtor(session, &hostkey_abstract);
    return 0;
}

int libssh2_sign_sk(LIBSSH2_SESSION *session,
                    unsigned char **sig, size_t *sig_len,
                    const unsigned char *data, size_t data_len,
                    void **abstract)
{
    int rc = LIBSSH2_ERROR_DECRYPT;
    LIBSSH2_PRIVKEY_SK *sk_info;
    LIBSSH2_SK_SIG_INFO sig_info = { 0 };

    if(!session || !abstract || !*abstract)
        return LIBSSH2_ERROR_BAD_USE;

    sk_info = (LIBSSH2_PRIVKEY_SK *)(*abstract);

    if(!sk_info->handle_len)
        return LIBSSH2_ERROR_DECRYPT;

    rc = sk_info->sign_callback(session,
                                &sig_info,
                                data,
                                data_len,
                                sk_info->algorithm,
                                sk_info->flags,
                                sk_info->application,
                                sk_info->key_handle,
                                sk_info->handle_len,
                                sk_info->orig_abstract);

    if(rc == 0 && sig_info.sig_r_len > 0 && sig_info.sig_r) {
        unsigned char *p = NULL;

        if(sig_info.sig_s_len > 0 && sig_info.sig_s) {
            /* sig length, sig_r, sig_s, flags, counter, plus 4 bytes for each
               component's length, and up to 1 extra byte for each component */
            *sig_len = 4 + 5 + sig_info.sig_r_len + 5 + sig_info.sig_s_len + 5;
            *sig = SSH2_ALLOC(session, *sig_len);

            if(*sig) {
                unsigned char *x = *sig;
                p = *sig;

                ssh2_store_u32(&p, 0);

                if(ssh2_store_bignum_bytes(&p, sig_info.sig_r,
                                           sig_info.sig_r_len) &&
                   ssh2_store_bignum_bytes(&p, sig_info.sig_s,
                                           sig_info.sig_s_len)) {
                    *sig_len = p - *sig;

                    ssh2_store_u32(&x, (uint32_t)(*sig_len - 4));
                }
                else {
                    ssh2_deb((session, LIBSSH2_ERROR_STORE_OVERFLOW,
                              "Write operation exceeded buffer size."));
                    rc = LIBSSH2_ERROR_STORE_OVERFLOW;
                    SSH2_SAFEFREE(session, *sig);
                    *sig_len = 0;
                    p = NULL;
                }
            }
            else {
                ssh2_deb((session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate ecdsa-sk signature."));
                rc = LIBSSH2_ERROR_ALLOC;
            }
        }
        else {
            /* sig, flags, counter, plus 4 bytes for sig length. */
            *sig_len = 4 + sig_info.sig_r_len + 1 + 4;
            *sig = SSH2_ALLOC(session, *sig_len);

            if(*sig) {
                p = *sig;
                ssh2_store_str(&p, (const char *)sig_info.sig_r,
                               sig_info.sig_r_len);
            }
            else {
                ssh2_deb((session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate ed25519-sk signature."));
                rc = LIBSSH2_ERROR_ALLOC;
            }
        }

        if(p) {
            *p = sig_info.flags;
            ++p;
            ssh2_store_u32(&p, sig_info.counter);

            *sig_len = p - *sig;
        }

        SSH2_FREE(session, sig_info.sig_r);

        if(sig_info.sig_s)
            SSH2_FREE(session, sig_info.sig_s);
    }
    else {
        ssh2_deb((session, LIBSSH2_ERROR_DECRYPT,
                  "sign_callback failed or returned invalid signature."));
        *sig_len = 0;
    }

    return rc;
}

/*
 * Authenticate using a keypair found in the named files
 */
static int userauth_hostbased_fromfile(LIBSSH2_SESSION *session,
                                       const char *username,
                                       size_t username_len,
                                       const char *publickey,
                                       const char *privatekey,
                                       const char *passphrase,
                                       const char *hostname,
                                       size_t hostname_len,
                                       const char *local_username,
                                       size_t local_username_len)
{
    int rc;

    if(session->userauth_host_state == ssh2_NB_state_idle) {
        const struct hostkey_method *privkeyobj;
        unsigned char *pubkeydata = NULL;
        unsigned char *sig = NULL;
        size_t pubkeydata_len = 0;
        size_t sig_len = 0;
        void *abstract;
        unsigned char buf[5];
        struct iovec datavec[4];

        /* Zero the whole thing out */
        memset(&session->userauth_host_packet_requirev_state, 0,
               sizeof(session->userauth_host_packet_requirev_state));

        if(publickey)
            rc = userauth_read_pubkey(session,
                                      &session->userauth_host_method,
                                      &session->userauth_host_method_len,
                                      &pubkeydata, &pubkeydata_len,
                                      publickey, NULL, 0);
        else /* Compute public key from private key. */
            rc = ssh2_pub_privkey(session,
                                  &session->userauth_host_method,
                                  &session->userauth_host_method_len,
                                  &pubkeydata, &pubkeydata_len,
                                  privatekey, NULL, 0, passphrase);

        if(rc)
            return rc; /* low-level functions called ssh2_err() */

        if(username_len > MAX_INPUT_LEN ||
           session->userauth_host_method_len > MAX_INPUT_LEN ||
           hostname_len > MAX_INPUT_LEN ||
           local_username_len > MAX_INPUT_LEN ||
           pubkeydata_len > MAX_INPUT_LEN) {
            SSH2_SAFEFREE(session, session->userauth_host_method);
            SSH2_FREE(session, pubkeydata);
            return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                            "Input parameter length too large");
        }

        /*
         * 52 = packet_type(1) + username_len(4) + servicename_len(4) +
         * service_name(14)"ssh-connection" + authmethod_len(4) +
         * authmethod(9)"hostbased" + method_len(4) + pubkeydata_len(4) +
         * hostname_len(4) + local_username_len(4)
         */
        session->userauth_host_packet_len =
            username_len + session->userauth_host_method_len + hostname_len +
            local_username_len + pubkeydata_len + 52;

        /*
         * Preallocate space for an overall length, method name again,
         * and the signature, which is not any larger than the size of
         * the publickeydata itself
         */
        session->userauth_host_s = session->userauth_host_packet =
            SSH2_ALLOC(session,
                       4 + session->userauth_host_packet_len +
                       4 + session->userauth_host_method_len +
                       4 + pubkeydata_len);
        if(!session->userauth_host_packet) {
            SSH2_SAFEFREE(session, session->userauth_host_method);
            SSH2_FREE(session, pubkeydata);
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC, "Out of memory");
        }

        *(session->userauth_host_s++) = SSH_MSG_USERAUTH_REQUEST;
        ssh2_store_str(&session->userauth_host_s, username, username_len);
        ssh2_store_str(&session->userauth_host_s, "ssh-connection", 14);
        ssh2_store_str(&session->userauth_host_s, "hostbased", 9);
        ssh2_store_str(&session->userauth_host_s,
                       session->userauth_host_method,
                       session->userauth_host_method_len);
        ssh2_store_str(&session->userauth_host_s, (const char *)pubkeydata,
                       pubkeydata_len);
        SSH2_FREE(session, pubkeydata);
        ssh2_store_str(&session->userauth_host_s, hostname, hostname_len);
        ssh2_store_str(&session->userauth_host_s, local_username,
                       local_username_len);

        rc = userauth_read_privkey(session, &privkeyobj, &abstract,
                                   session->userauth_host_method,
                                   session->userauth_host_method_len,
                                   privatekey, NULL, 0, passphrase);
        if(rc) {
            /* userauth_read_privkey() calls ssh2_err() */
            SSH2_SAFEFREE(session, session->userauth_host_method);
            SSH2_SAFEFREE(session, session->userauth_host_packet);
            return rc;
        }

        ssh2_htonu32(buf, session->session_id_len);
        ssh2_prepare_iovec(datavec, 4);
        datavec[0].iov_base = (void *)buf;
        datavec[0].iov_len = 4;
        datavec[1].iov_base = (void *)session->session_id;
        datavec[1].iov_len = session->session_id_len;
        datavec[2].iov_base = (void *)session->userauth_host_packet;
        datavec[2].iov_len = session->userauth_host_packet_len;

        if(privkeyobj && privkeyobj->signv &&
           privkeyobj->signv(session, &sig, &sig_len, 3, datavec, &abstract)) {
            SSH2_SAFEFREE(session, session->userauth_host_method);
            SSH2_SAFEFREE(session, session->userauth_host_packet);
            if(privkeyobj->dtor)
                privkeyobj->dtor(session, &abstract);
            return -1;
        }

        if(privkeyobj && privkeyobj->dtor)
            privkeyobj->dtor(session, &abstract);

        if(sig_len > pubkeydata_len) {
            unsigned char *newpacket;
            /* Should *NEVER* happen, but...well.. better safe than sorry */
            newpacket = SSH2_REALLOC(session, session->userauth_host_packet,
                                     4 + session->userauth_host_packet_len +
                                     4 + session->userauth_host_method_len +
                                     4 + sig_len); /* PK sigblob */
            if(!newpacket) {
                SSH2_FREE(session, sig);
                SSH2_SAFEFREE(session, session->userauth_host_packet);
                SSH2_SAFEFREE(session, session->userauth_host_method);
                return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                                "Failed allocating additional space for "
                                "userauth-hostbased packet");
            }
            session->userauth_host_packet = newpacket;
        }

        session->userauth_host_s =
            session->userauth_host_packet + session->userauth_host_packet_len;

        ssh2_store_u32(&session->userauth_host_s,
                       (uint32_t)(4 + session->userauth_host_method_len + 4 +
                                  sig_len));
        ssh2_store_str(&session->userauth_host_s,
                       session->userauth_host_method,
                       session->userauth_host_method_len);
        SSH2_SAFEFREE(session, session->userauth_host_method);

        ssh2_store_str(&session->userauth_host_s, (const char *)sig, sig_len);
        SSH2_FREE(session, sig);

        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Attempting hostbased authentication"));

        session->userauth_host_state = ssh2_NB_state_created;
    }

    if(session->userauth_host_state == ssh2_NB_state_created) {
        rc = ssh2_transport_send(session, session->userauth_host_packet,
                                 session->userauth_host_s -
                                 session->userauth_host_packet,
                                 NULL, 0);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
        else if(rc) {
            SSH2_SAFEFREE(session, session->userauth_host_packet);
            session->userauth_host_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                            "Unable to send userauth-hostbased request");
        }
        SSH2_SAFEFREE(session, session->userauth_host_packet);

        session->userauth_host_state = ssh2_NB_state_sent;
    }

    if(session->userauth_host_state == ssh2_NB_state_sent) {
        static const unsigned char reply_codes[3] = {
            SSH_MSG_USERAUTH_SUCCESS,
            SSH_MSG_USERAUTH_FAILURE,
            0
        };
        size_t data_len;
        rc = ssh2_packet_requirev(session, reply_codes,
                                  &session->userauth_host_data,
                                  &data_len, 0, NULL, 0,
                                  &session->
                                  userauth_host_packet_requirev_state);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");

        session->userauth_host_state = ssh2_NB_state_idle;
        if(rc || data_len < 1)
            return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                            "Auth failed");

        if(session->userauth_host_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
            ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                      "Hostbased authentication successful"));
            /* We are us and we have proved it. */
            SSH2_SAFEFREE(session, session->userauth_host_data);
            session->state |= SSH2_STATE_AUTHENTICATED;
            return 0;
        }
    }

    /* This public key is not allowed for this user on this server */
    SSH2_SAFEFREE(session, session->userauth_host_data);
    return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                    "Invalid signature for supplied public key, or bad "
                    "username/public key combination");
}

/*
 * Authenticate using a keypair found in the named files
 */
int libssh2_userauth_hostbased_fromfile_ex(LIBSSH2_SESSION *session,
                                           const char *username,
                                           unsigned int username_len,
                                           const char *publickey,
                                           const char *privatekey,
                                           const char *passphrase,
                                           const char *hostname,
                                           unsigned int hostname_len,
                                           const char *local_username,
                                           unsigned int local_username_len)
{
    int rc;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    BLOCK_ADJUST(rc, session,
                 userauth_hostbased_fromfile(session,
                                             username, username_len,
                                             publickey, privatekey,
                                             passphrase,
                                             hostname, hostname_len,
                                             local_username,
                                             local_username_len));
    return rc;
}

size_t ssh2_userauth_plain_method(char *method, size_t method_len)
{
    if(!strncmp("ssh-rsa-cert-v01@openssh.com",
                method, method_len))
        return 7;

    if(!strncmp("rsa-sha2-256-cert-v01@openssh.com",
                method, method_len) ||
       !strncmp("rsa-sha2-512-cert-v01@openssh.com",
                method, method_len))
        return 12;

    if(!strncmp("ecdsa-sha2-nistp256-cert-v01@openssh.com",
                method, method_len) ||
       !strncmp("ecdsa-sha2-nistp384-cert-v01@openssh.com",
                method, method_len) ||
       !strncmp("ecdsa-sha2-nistp521-cert-v01@openssh.com",
                method, method_len))
        return 19;

    if(!strncmp("ssh-ed25519-cert-v01@openssh.com",
                method, method_len))
        return 11;

    if(!strncmp("sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
                method, method_len)) {
        const char new_method[] = "sk-ecdsa-sha2-nistp256@openssh.com";
        memcpy(method, new_method, sizeof(new_method));
        return sizeof(new_method) - 1;
    }

    if(!strncmp("sk-ssh-ed25519-cert-v01@openssh.com",
                method, method_len)) {
        const char new_method[] = "sk-ssh-ed25519@openssh.com";
        memcpy(method, new_method, sizeof(new_method));
        return sizeof(new_method) - 1;
    }

    return method_len;
}

/* Function to check if the given version is less than pattern (OpenSSH 7.8)
 * This function expects the input version in x.y* format
 * (x being openssh major and y being openssh minor version)
 * Returns 1 if the version is less than OpenSSH_7.8, 0 otherwise
 */
static int userauth_is_version_less_than_78(const char *version)
{
    char *endptr_major = NULL;
    char *endptr_minor = NULL;
    long major = 0;
    long minor = 0;

    if(!version)
        return 0;

    /* !checksrc! disable BANNEDFUNC 1 */
    major = strtol(version, &endptr_major, 10);
    if(!endptr_major || *endptr_major != '.')
        return 0; /* Not a valid number */

    /* !checksrc! disable BANNEDFUNC 1 */
    minor = strtol(endptr_major + 1, &endptr_minor, 10);
    if(!endptr_minor || endptr_minor == endptr_major + 1)
        return 0; /* Not a valid number */

    if((major >= 1 && major <= 6) ||
       (major == 7 && minor >= 0 && minor <= 7))
        return 1; /* Version is in the specified range */

    return 0;
}

/**
 * @abstract Returns supported algorithms used for upgrading public
 * key signing RFC 8332
 * @discussion Based on the incoming 'method' value, this function
 * returns supported algorithms that can upgrade the key method
 * @param method current key method, usually the default key sig method
 * @param method_len length of the key method buffer
 * @result comma separated list of supported upgrade options per RFC 8332, if
 * there is no upgrade option return NULL
 */
static const char *userauth_supported_key_sign_algs(LIBSSH2_SESSION *session,
                                                    const char *method,
                                                    size_t method_len)
{
    (void)session;

#if LIBSSH2_RSA_SHA2
    if((method_len == 7 &&
        !memcmp(method, "ssh-rsa", method_len))
#if defined(LIBSSH2_OPENSSL) || defined(LIBSSH2_WOLFSSL)
       || (method_len == 28 &&
           !memcmp(method, "ssh-rsa-cert-v01@openssh.com", method_len))
#endif
      ) {
        return "rsa-sha2-512,rsa-sha2-256"
#if LIBSSH2_RSA_SHA1
            ",ssh-rsa"
#endif
            ;
    }
#else
    (void)method;
    (void)method_len;
#endif

    return NULL;
}

/**
 * @abstract Upgrades the algorithm used for public key signing RFC 8332
 * @discussion Based on the incoming 'method' value, this function
 * Upgrades the key method input based on user preferences,
 * server support algos and crypto backend support
 * @related userauth_supported_key_sign_algs()
 * @param method current key method, usually the default key sig method
 * @param method_len length of the key method buffer
 * @result error code or zero on success
 */
static int userauth_key_sign_algs(LIBSSH2_SESSION *session,
                                  char **method, size_t *method_len)
{
    const char *s = NULL;
    const char *a = NULL;
    const char *match = NULL;
    const char *p = NULL;
    const char *f = NULL;
    char *i = NULL;
    size_t p_len = 0;
    size_t f_len = 0;
    int rc = 0;
    size_t match_len = 0;
    char *filtered_algs = NULL;
    const size_t suffix_len = sizeof("-cert-v01@openssh.com") - 1;
    const char * const suffix = "-cert-v01@openssh.com";
    const size_t rsa_method_len = sizeof("ssh-rsa-cert-v01@openssh.com") - 1;
    const char * const rsa_method = "ssh-rsa-cert-v01@openssh.com";
    const char *remote_banner = NULL;
    const char * const remote_ver_pre = "OpenSSH_";

    const char *supported_algs = userauth_supported_key_sign_algs(session,
                                                                  *method,
                                                                  *method_len);

    if(!supported_algs || !session->server_sign_algorithms)
        /* no upgrading key algorithm supported, do nothing */
        return LIBSSH2_ERROR_NONE;

    /* Set "SSH_BUG_SIGTYPE" flag when the remote server version is OpenSSH 7.7
       or lower and when the RSA key in question is a certificate to ignore
       "server-sig-algs" and only offer ssh-rsa signature algorithm for
       RSA certs */
    remote_banner = libssh2_session_banner_get(session);
    /* Extract version information from the banner */
    if(remote_banner) {
        const char *remote_ver_start = strstr(remote_banner, remote_ver_pre);
        if(remote_ver_start) {
            const char *remote_ver = remote_ver_start + strlen(remote_ver_pre);
            int SSH_BUG_SIGTYPE = userauth_is_version_less_than_78(remote_ver);
            if(SSH_BUG_SIGTYPE && *method && *method_len == rsa_method_len &&
               !memcmp(*method, rsa_method, rsa_method_len))
                return LIBSSH2_ERROR_NONE;
        }
    }

    filtered_algs = SSH2_ALLOC(session,
                               strlen(session->server_sign_algorithms) + 1);
    if(!filtered_algs) {
        rc = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                      "Unable to allocate filtered algs");
        return rc;
    }

    s = session->server_sign_algorithms;
    i = filtered_algs;

    /* this walks the server algo list and the supported algo list and creates
       a filtered list that includes matches */

    while(s && *s) {
        p = strchr(s, ',');
        p_len = p ? (size_t)(p - s) : strlen(s);
        a = supported_algs;

        while(a && *a) {
            f = strchr(a, ',');
            f_len = f ? (size_t)(f - a) : strlen(a);

            if(f_len == p_len && !memcmp(a, s, p_len)) {

                if(i != filtered_algs) {
                    memcpy(i, ",", 1);
                    i += 1;
                }

                memcpy(i, s, p_len);
                i += p_len;
            }

            a = f ? (f + 1) : NULL;
        }

        s = p ? (p + 1) : NULL;
    }

    *i = '\0';

    s = session->sign_algo_prefs ? session->sign_algo_prefs : supported_algs;

    /* now that we have the possible supported algos, match based on the prefs
       or what is supported by the crypto backend, look for a match */

    while(s && *s && !match) {
        p = strchr(s, ',');
        p_len = p ? (size_t)(p - s) : strlen(s);
        a = filtered_algs;

        while(a && *a && !match) {
            f = strchr(a, ',');
            f_len = f ? (size_t)(f - a) : strlen(a);

            if(f_len == p_len && !memcmp(a, s, p_len)) {
                /* found a match, upgrade key method */
                match = s;
                match_len = p_len;
            }
            else
                a = f ? (f + 1) : NULL;
        }

        s = p ? (p + 1) : NULL;
    }

    if(match) {
        if(*method && *method_len == rsa_method_len &&
           !memcmp(*method, rsa_method, rsa_method_len)) {
            SSH2_FREE(session, *method);
            *method = SSH2_ALLOC(session, match_len + suffix_len + 1);
            if(*method) {
                memcpy(*method, match, match_len);
                memcpy(*method + match_len, suffix, suffix_len);
                (*method)[match_len + suffix_len] = 0;
                *method_len = match_len + suffix_len;
            }
        }
        else {
            if(*method)
                SSH2_FREE(session, *method);
            *method = SSH2_ALLOC(session, match_len + 1);
            if(*method) {
                memcpy(*method, match, match_len);
                method[match_len] = 0;
                *method_len = match_len;
            }
        }
        if(!*method) {
            *method_len = 0;
            rc = ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate key method upgrade");
        }
    }
    else /* no match was found */
        rc = ssh2_err(session, LIBSSH2_ERROR_METHOD_NONE,
                      "No signing signature matched");

    SSH2_FREE(session, filtered_algs);

    return rc;
}

int ssh2_userauth_publickey(
    LIBSSH2_SESSION *session,
    const char *username, size_t username_len,
    const unsigned char *pubkeydata, size_t pubkeydata_len,
    LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(*sign_callback),
    void *abstract)
{
    unsigned char reply_codes[4] = {
        SSH_MSG_USERAUTH_SUCCESS,
        SSH_MSG_USERAUTH_FAILURE,
        SSH_MSG_USERAUTH_PK_OK,
        0
    };
    int rc;
    unsigned char *s;
    int auth_attempts = 0;

retry_auth:
    auth_attempts++;

    if(session->userauth_pblc_state == ssh2_NB_state_idle) {

        /*
         * The call to ssh2_ntohu32() later relies on pubkeydata having at
         * least 4 valid bytes containing the length of the method name.
         */
        if(pubkeydata_len < 4)
            return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                            "Invalid public key, too short");

        /*
         * Cap caller-supplied input lengths early, before any allocation
         * derived from them. This bounds packet-size arithmetic and the
         * method-length parse below.
         */
        if(username_len > MAX_INPUT_LEN ||
           pubkeydata_len > MAX_INPUT_LEN)
            return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                            "Username or public key length too large");

        /* Zero the whole thing out */
        memset(&session->userauth_pblc_packet_requirev_state, 0,
               sizeof(session->userauth_pblc_packet_requirev_state));

        /*
         * As an optimisation, userauth_publickey() reuses a previously
         * allocated copy of the method name to avoid an extra allocation/free.
         * For other uses, we allocate and populate it here.
         */
        if(!session->userauth_pblc_method) {
            size_t method_len = ssh2_ntohu32(pubkeydata);

            if(method_len == 0 ||
               method_len > MAX_INPUT_LEN ||
               method_len > pubkeydata_len - 4)
                /* the method length cannot be longer than the entire passed
                   in data, so we use this to detect crazy input data */
                return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                                "Invalid public key");

            session->userauth_pblc_method_len = 0;
            session->userauth_pblc_method =
                SSH2_ALLOC(session, method_len + 1);
            if(!session->userauth_pblc_method)
                return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                                "Unable to allocate memory "
                                "for public key data");
            session->userauth_pblc_method_len = method_len;
            memcpy(session->userauth_pblc_method, pubkeydata + 4, method_len);
            session->userauth_pblc_method[method_len] = 0;
        }

        /* upgrade key signing algo if it is supported and
         * it is our first auth attempt, otherwise fallback to
         * the key default algo */
        if(auth_attempts == 1) {
            rc = userauth_key_sign_algs(session,
                                        &session->userauth_pblc_method,
                                        &session->userauth_pblc_method_len);
            if(rc)
                return rc;
        }

        if(session->userauth_pblc_method_len &&
           session->userauth_pblc_method)
            ssh2_deb((session, LIBSSH2_TRACE_KEX, "Signing using %.*s",
                      (int)session->userauth_pblc_method_len,
                      session->userauth_pblc_method));

        /* 45 = packet_type(1) + username_len(4) + servicename_len(4) +
           service_name(14)"ssh-connection" + authmethod_len(4) +
           authmethod(9)"publickey" + sig_included(1)'\0' + algmethod_len(4) +
           publickey_len(4) */
        session->userauth_pblc_packet_len =
            username_len + session->userauth_pblc_method_len + pubkeydata_len +
            45;

        /*
         * Preallocate space for an overall length, method name again, and the
         * signature, which is not any larger than the size of the
         * publickeydata itself.
         *
         * Note that the 'pubkeydata_len' extra bytes allocated here are not
         * used in this first send, but are used in the later one where
         * this same allocation is reused.
         */
        session->userauth_pblc_packet = s =
            SSH2_ALLOC(session,
                       4 + session->userauth_pblc_packet_len +
                       4 + session->userauth_pblc_method_len +
                       4 + pubkeydata_len);
        if(!session->userauth_pblc_packet) {
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC, "Out of memory");
        }

        *s++ = SSH_MSG_USERAUTH_REQUEST;
        ssh2_store_str(&s, username, username_len);
        ssh2_store_str(&s, "ssh-connection", 14);
        ssh2_store_str(&s, "publickey", 9);

        session->userauth_pblc_b = s;
        /* Not sending signature with *this* packet */
        *s++ = 0;

        ssh2_store_str(&s, session->userauth_pblc_method,
                           session->userauth_pblc_method_len);
        ssh2_store_str(&s, (const char *)pubkeydata, pubkeydata_len);

        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Attempting publickey authentication"));

        session->userauth_pblc_state = ssh2_NB_state_created;
    }

    if(session->userauth_pblc_state == ssh2_NB_state_created) {
        rc = ssh2_transport_send(session, session->userauth_pblc_packet,
                                 session->userauth_pblc_packet_len, NULL, 0);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
        else if(rc) {
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            session->userauth_pblc_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                            "Unable to send userauth-publickey request");
        }

        session->userauth_pblc_state = ssh2_NB_state_sent;
    }

    if(session->userauth_pblc_state == ssh2_NB_state_sent) {
        rc = ssh2_packet_requirev(session, reply_codes,
                                  &session->userauth_pblc_data,
                                  &session->userauth_pblc_data_len, 0,
                                  NULL, 0,
                                  &session->
                                  userauth_pblc_packet_requirev_state);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
        else if(rc || session->userauth_pblc_data_len < 1) {
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            session->userauth_pblc_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                            "Waiting for USERAUTH response");
        }

        if(session->userauth_pblc_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
            ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                      "Pubkey authentication prematurely successful"));
            /*
             * God help any SSH server that allows an UNVERIFIED
             * public key to validate the user
             */
            SSH2_SAFEFREE(session, session->userauth_pblc_data);
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            session->state |= SSH2_STATE_AUTHENTICATED;
            session->userauth_pblc_state = ssh2_NB_state_idle;
            return 0;
        }

        if(session->userauth_pblc_data[0] == SSH_MSG_USERAUTH_FAILURE) {
            /* This public key is not allowed for this user on this server */
            SSH2_SAFEFREE(session, session->userauth_pblc_data);
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            session->userauth_pblc_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_AUTHENTICATION_FAILED,
                            "Username/PublicKey combination invalid");
        }

        /* Semi-Success! */
        SSH2_SAFEFREE(session, session->userauth_pblc_data);

        *session->userauth_pblc_b = 0x01;
        session->userauth_pblc_state = ssh2_NB_state_sent1;
    }

    if(session->userauth_pblc_state == ssh2_NB_state_sent1) {
        unsigned char *buf;
        unsigned char *sig = NULL;
        size_t sig_len;

        s = buf = SSH2_ALLOC(session,
                             4 + session->session_id_len +
                             session->userauth_pblc_packet_len);
        if(!buf)
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for "
                            "userauth-publickey signed data");

        ssh2_store_str(&s, (const char *)session->session_id,
                       session->session_id_len);

        memcpy(s, session->userauth_pblc_packet,
               session->userauth_pblc_packet_len);
        s += session->userauth_pblc_packet_len;

        rc = sign_callback(session, &sig, &sig_len, buf, s - buf, abstract);
        SSH2_FREE(session, buf);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
        else if(rc == LIBSSH2_ERROR_ALGO_UNSUPPORTED && auth_attempts == 1) {
            /* try again with the default key algo */
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_state = ssh2_NB_state_idle;

            goto retry_auth;
        }
        else if(rc) {
            SSH2_SAFEFREE(session, session->userauth_pblc_method);
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                            "Callback returned error");
        }

        if(!sig)
            return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                            "Callback did not return signature");

        /*
         * If this function was restarted, pubkeydata_len might still be 0
         * which causes an unnecessary but harmless realloc here.
         */
        if(sig_len > pubkeydata_len) {
            unsigned char *newpacket;
            /* Should *NEVER* happen, but...well.. better safe than sorry */
            newpacket = SSH2_REALLOC(session,
                                     session->userauth_pblc_packet,
                                     4 + session->userauth_pblc_packet_len +
                                     4 + session->userauth_pblc_method_len +
                                     4 + sig_len); /* PK sigblob */
            if(!newpacket) {
                SSH2_FREE(session, sig);
                SSH2_SAFEFREE(session, session->userauth_pblc_packet);
                SSH2_SAFEFREE(session, session->userauth_pblc_method);
                session->userauth_pblc_state = ssh2_NB_state_idle;
                return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                                "Failed allocating additional space for "
                                "userauth-publickey packet");
            }
            session->userauth_pblc_packet = newpacket;
        }

        s = session->userauth_pblc_packet + session->userauth_pblc_packet_len;
        session->userauth_pblc_b = NULL;

        session->userauth_pblc_method_len =
            ssh2_userauth_plain_method(session->userauth_pblc_method,
                                       session->userauth_pblc_method_len);

        if(!strncmp(session->userauth_pblc_method,
                    "sk-ecdsa-sha2-nistp256@openssh.com",
                    session->userauth_pblc_method_len) ||
           !strncmp(session->userauth_pblc_method,
                    "sk-ssh-ed25519@openssh.com",
                    session->userauth_pblc_method_len)) {
            ssh2_store_u32(&s,
                           (uint32_t)(4 + session->userauth_pblc_method_len +
                                      sig_len));
            ssh2_store_str(&s, session->userauth_pblc_method,
                               session->userauth_pblc_method_len);
            memcpy(s, sig, sig_len);
            s += sig_len;
        }
        else {
            ssh2_store_u32(&s,
                           (uint32_t)(4 + session->userauth_pblc_method_len +
                                      4 + sig_len));
            ssh2_store_str(&s, session->userauth_pblc_method,
                               session->userauth_pblc_method_len);
            ssh2_store_str(&s, (const char *)sig, sig_len);
        }

        SSH2_SAFEFREE(session, session->userauth_pblc_method);
        SSH2_FREE(session, sig);

        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Attempting publickey authentication -- phase 2"));

        session->userauth_pblc_s = s;
        session->userauth_pblc_state = ssh2_NB_state_sent2;
    }

    if(session->userauth_pblc_state == ssh2_NB_state_sent2) {
        rc = ssh2_transport_send(session, session->userauth_pblc_packet,
                                 session->userauth_pblc_s -
                                 session->userauth_pblc_packet,
                                 NULL, 0);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
        else if(rc) {
            SSH2_SAFEFREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                            "Unable to send userauth-publickey request");
        }
        SSH2_SAFEFREE(session, session->userauth_pblc_packet);

        session->userauth_pblc_state = ssh2_NB_state_sent3;
    }

    /* PK_OK is no longer valid */
    reply_codes[2] = 0;

    rc = ssh2_packet_requirev(session, reply_codes,
                              &session->userauth_pblc_data,
                              &session->userauth_pblc_data_len, 0, NULL, 0,
                              &session->userauth_pblc_packet_requirev_state);
    if(rc == LIBSSH2_ERROR_EAGAIN)
        return ssh2_err(session, LIBSSH2_ERROR_EAGAIN,
                        "Would block waiting for publickey USERAUTH response");
    else if(rc || session->userauth_pblc_data_len < 1) {
        session->userauth_pblc_state = ssh2_NB_state_idle;
        return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                        "Waiting for publickey USERAUTH response");
    }

    if(session->userauth_pblc_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Publickey authentication successful"));
        /* We are us and we have proved it. */
        SSH2_SAFEFREE(session, session->userauth_pblc_data);
        session->state |= SSH2_STATE_AUTHENTICATED;
        session->userauth_pblc_state = ssh2_NB_state_idle;
        return 0;
    }

    /* This public key is not allowed for this user on this server */
    SSH2_SAFEFREE(session, session->userauth_pblc_data);
    session->userauth_pblc_state = ssh2_NB_state_idle;
    return ssh2_err(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                    "Invalid signature for supplied public key, or bad "
                    "username/public key combination");
}

/*
 * Authenticate using a keypair from file or blob
 */
static int userauth_publickey(LIBSSH2_SESSION *session,
                              const char *username,  size_t username_len,
                              const char *pubkeyfile,
                              const char *pubkeyblob, size_t pubkeyblob_len,
                              const char *privkeyfile,
                              const char *privkeyblob, size_t privkeyblob_len,
                              const char *passphrase)
{
    unsigned char *pubkeydata = NULL;
    size_t pubkeydata_len = 0;
    struct privkey_info privkey_info;
    void *abstract = &privkey_info;
    int rc;

    privkey_info.filename = privkeyfile;
    privkey_info.data = privkeyblob;
    privkey_info.data_len = privkeyblob_len;
    privkey_info.passphrase = passphrase;

    if(session->userauth_pblc_state == ssh2_NB_state_idle) {
        if(pubkeyfile || (pubkeyblob && pubkeyblob_len))
            rc = userauth_read_pubkey(session,
                                      &session->userauth_pblc_method,
                                      &session->userauth_pblc_method_len,
                                      &pubkeydata, &pubkeydata_len,
                                      pubkeyfile, pubkeyblob, pubkeyblob_len);
        /* Compute public key from private key. */
        else if(privkeyfile || (privkeyblob && privkeyblob_len))
            rc = ssh2_pub_privkey(session,
                                  &session->userauth_pblc_method,
                                  &session->userauth_pblc_method_len,
                                  &pubkeydata, &pubkeydata_len,
                                  privkeyfile, privkeyblob, privkeyblob_len,
                                  passphrase);
        else
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Invalid data in public and private key.");

        if(rc)
            return rc; /* low-level functions called ssh2_err() */
    }

    rc = ssh2_userauth_publickey(session, username, username_len,
                                 pubkeydata, pubkeydata_len,
                                 userauth_sign, &abstract);
    if(pubkeydata)
        SSH2_FREE(session, pubkeydata);

    return rc;
}

/*
 * Authenticate using a keypair from memory
 */
int libssh2_userauth_publickey_frommemory(LIBSSH2_SESSION *session,
                                          const char *username,
                                          size_t username_len,
                                          const char *pubkeyblob,
                                          size_t pubkeyblob_len,
                                          const char *privkeyblob,
                                          size_t privkeyblob_len,
                                          const char *passphrase)
{
    int rc;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    if(!passphrase)
        /* if given a NULL pointer, make it point to a zero-length
           string to save us from having to check this all over */
        passphrase = "";

    BLOCK_ADJUST(rc, session,
                 userauth_publickey(session,
                                    username, username_len,
                                    NULL, pubkeyblob, pubkeyblob_len,
                                    NULL, privkeyblob, privkeyblob_len,
                                    passphrase));
    return rc;
}

/*
 * Authenticate using a keypair found in the named files
 */
int libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION *session,
                                           const char *username,
                                           unsigned int username_len,
                                           const char *publickey,
                                           const char *privatekey,
                                           const char *passphrase)
{
    int rc;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    if(!passphrase)
        /* if given a NULL pointer, make it point to a zero-length
           string to save us from having to check this all over */
        passphrase = "";

    BLOCK_ADJUST(rc, session,
                 userauth_publickey(session,
                                    username, username_len,
                                    publickey, NULL, 0,
                                    privatekey, NULL, 0,
                                    passphrase));
    return rc;
}

/*
 * Authenticate using an external callback function
 */
int libssh2_userauth_publickey(
    LIBSSH2_SESSION *session,
    const char *username,
    const unsigned char *pubkeydata, size_t pubkeydata_len,
    LIBSSH2_USERAUTH_PUBLICKEY_SIGN_FUNC(*sign_callback),
    void **abstract)
{
    int rc;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    BLOCK_ADJUST(rc, session,
                 ssh2_userauth_publickey(session,
                                         username, strlen(username),
                                         pubkeydata, pubkeydata_len,
                                         sign_callback, abstract));
    return rc;
}

/*
 * Authenticate using a challenge-response authentication
 */
static int userauth_keyboard_interactive(
    LIBSSH2_SESSION *session,
    const char *username, unsigned int username_len,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(*response_callback))
{
    static const unsigned char reply_codes[4] = {
        SSH_MSG_USERAUTH_SUCCESS,
        SSH_MSG_USERAUTH_FAILURE,
        SSH_MSG_USERAUTH_INFO_REQUEST,
        0
    };

    int rc;
    unsigned char *s;
    unsigned int i;
    size_t packet_len;

    if(session->userauth_kybd_state == ssh2_NB_state_idle) {
        session->userauth_kybd_auth_name = NULL;
        session->userauth_kybd_auth_instruction = NULL;
        session->userauth_kybd_num_prompts = 0;
        session->userauth_kybd_auth_failure = 1;
        session->userauth_kybd_prompts = NULL;
        session->userauth_kybd_responses = NULL;

        /* Zero the whole thing out */
        memset(&session->userauth_kybd_packet_requirev_state, 0,
               sizeof(session->userauth_kybd_packet_requirev_state));

        if(username_len > MAX_INPUT_LEN)
            return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                            "Username too long");

        packet_len =
            1                   /* byte    SSH_MSG_USERAUTH_REQUEST */
            + 4 + username_len  /* string  username (ISO-10646 UTF-8, as
                                   defined in [RFC-3629]) */
            + 4 + 14            /* string  service name (US-ASCII) */
            + 4 + 20            /* string  "keyboard-interactive" (US-ASCII) */
            + 4 + 0             /* string  language tag (as defined in
                                   [RFC-3066]) */
            + 4 + 0             /* string  submethods (ISO-10646 UTF-8) */
            ;

        session->userauth_kybd_packet_len = 0;
        session->userauth_kybd_data = s = SSH2_ALLOC(session, packet_len);
        if(!s)
            return ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                            "Unable to allocate memory for "
                            "keyboard-interactive authentication");
        session->userauth_kybd_packet_len = packet_len;

        *s++ = SSH_MSG_USERAUTH_REQUEST;

        /* username */
        ssh2_store_str(&s, username, username_len);

        /* service name */
        ssh2_store_str(&s, "ssh-connection", sizeof("ssh-connection") - 1);

        /* "keyboard-interactive" */
        ssh2_store_str(&s, "keyboard-interactive",
                       sizeof("keyboard-interactive") - 1);
        /* language tag */
        ssh2_store_u32(&s, 0);

        /* submethods */
        ssh2_store_u32(&s, 0);

        ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                  "Attempting keyboard-interactive authentication"));

        session->userauth_kybd_state = ssh2_NB_state_created;
    }

    if(session->userauth_kybd_state == ssh2_NB_state_created) {
        rc = ssh2_transport_send(session, session->userauth_kybd_data,
                                 session->userauth_kybd_packet_len, NULL, 0);
        if(rc == LIBSSH2_ERROR_EAGAIN)
            return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
        else if(rc) {
            SSH2_SAFEFREE(session, session->userauth_kybd_data);
            session->userauth_kybd_state = ssh2_NB_state_idle;
            return ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                            "Unable to send keyboard-interactive request");
        }
        SSH2_SAFEFREE(session, session->userauth_kybd_data);

        session->userauth_kybd_state = ssh2_NB_state_sent;
    }

    for(;;) {
        if(session->userauth_kybd_state == ssh2_NB_state_sent) {
            rc = ssh2_packet_requirev(session, reply_codes,
                                      &session->userauth_kybd_data,
                                      &session->userauth_kybd_data_len,
                                      0, NULL, 0,
                                      &session->
                                      userauth_kybd_packet_requirev_state);
            if(rc == LIBSSH2_ERROR_EAGAIN)
                return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
            else if(rc || session->userauth_kybd_data_len < 1) {
                session->userauth_kybd_state = ssh2_NB_state_idle;
                return ssh2_err(session, LIBSSH2_ERROR_AUTHENTICATION_FAILED,
                                "Waiting for keyboard USERAUTH response");
            }

            if(session->userauth_kybd_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
                ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                          "Keyboard-interactive authentication successful"));
                SSH2_SAFEFREE(session, session->userauth_kybd_data);
                session->state |= SSH2_STATE_AUTHENTICATED;
                session->userauth_kybd_state = ssh2_NB_state_idle;
                return 0;
            }

            if(session->userauth_kybd_data[0] == SSH_MSG_USERAUTH_FAILURE) {
                ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                          "Keyboard-interactive authentication failed"));
                SSH2_SAFEFREE(session, session->userauth_kybd_data);
                session->userauth_kybd_state = ssh2_NB_state_idle;
                return ssh2_err(session, LIBSSH2_ERROR_AUTHENTICATION_FAILED,
                                "Authentication failed "
                                "(keyboard-interactive)");
            }

            /* server requested PAM-like conversation */
            if(userauth_keyboard_interactive_decode_info_request(session) < 0)
                goto cleanup;

            response_callback((const char *)session->userauth_kybd_auth_name,
                              (int)session->userauth_kybd_auth_name_len,
                              (const char *)
                              session->userauth_kybd_auth_instruction,
                              (int)session->userauth_kybd_auth_instruction_len,
                              session->userauth_kybd_num_prompts,
                              session->userauth_kybd_prompts,
                              session->userauth_kybd_responses,
                              &session->abstract);

            ssh2_deb((session, LIBSSH2_TRACE_AUTH,
                      "Keyboard-interactive response callback function"
                      " invoked"));

            packet_len =
                1    /* byte      SSH_MSG_USERAUTH_INFO_RESPONSE */
                + 4  /* int       num-responses */
                ;

            for(i = 0; i < session->userauth_kybd_num_prompts; i++) {
                /* string    response[1] (ISO-10646 UTF-8) */
                if(session->userauth_kybd_responses[i].length <=
                   (SIZE_MAX - 4 - packet_len))
                    packet_len +=
                        4 + (size_t)session->userauth_kybd_responses[i].length;
                else {
                    ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                             "keyboard-interactive response packet too large");
                    goto cleanup;
                }
            }

            /* A new userauth_kybd_data area is to be allocated, free the
               former one. */
            SSH2_FREE(session, session->userauth_kybd_data);
            session->userauth_kybd_packet_len = 0;
            session->userauth_kybd_data = s = SSH2_ALLOC(session, packet_len);
            if(!s) {
                ssh2_err(session, LIBSSH2_ERROR_ALLOC,
                         "Unable to allocate memory for "
                         "keyboard-interactive response packet");
                goto cleanup;
            }
            session->userauth_kybd_packet_len = packet_len;

            *s = SSH_MSG_USERAUTH_INFO_RESPONSE;
            s++;
            ssh2_store_u32(&s, session->userauth_kybd_num_prompts);

            for(i = 0; i < session->userauth_kybd_num_prompts; i++)
                ssh2_store_str(&s, session->userauth_kybd_responses[i].text,
                               session->userauth_kybd_responses[i].length);

            session->userauth_kybd_state = ssh2_NB_state_sent1;
        }

        if(session->userauth_kybd_state == ssh2_NB_state_sent1) {
            rc = ssh2_transport_send(session, session->userauth_kybd_data,
                                     session->userauth_kybd_packet_len,
                                     NULL, 0);
            if(rc == LIBSSH2_ERROR_EAGAIN)
                return ssh2_err(session, LIBSSH2_ERROR_EAGAIN, "Would block");
            if(rc) {
                ssh2_err(session, LIBSSH2_ERROR_SOCKET_SEND,
                         "Unable to send keyboard-interactive response");
                goto cleanup;
            }

            session->userauth_kybd_auth_failure = 0;
        }

cleanup:
        /*
         * It is safe to clean all the data here, because unallocated pointers
         * are filled by zeroes
         */

        SSH2_SAFEFREE(session, session->userauth_kybd_data);

        if(session->userauth_kybd_prompts)
            for(i = 0; i < session->userauth_kybd_num_prompts; i++)
                SSH2_SAFEFREE(session, session->userauth_kybd_prompts[i].text);

        if(session->userauth_kybd_responses)
            for(i = 0; i < session->userauth_kybd_num_prompts; i++)
                SSH2_SAFEFREE(session,
                              session->userauth_kybd_responses[i].text);

        if(session->userauth_kybd_prompts)
            SSH2_SAFEFREE(session, session->userauth_kybd_prompts);
        if(session->userauth_kybd_responses)
            SSH2_SAFEFREE(session, session->userauth_kybd_responses);
        if(session->userauth_kybd_auth_name)
            SSH2_SAFEFREE(session, session->userauth_kybd_auth_name);
        if(session->userauth_kybd_auth_instruction)
            SSH2_SAFEFREE(session, session->userauth_kybd_auth_instruction);

        if(session->userauth_kybd_auth_failure) {
            session->userauth_kybd_state = ssh2_NB_state_idle;
            return -1;
        }

        session->userauth_kybd_state = ssh2_NB_state_sent;
    }
}

/*
 * Authenticate using a challenge-response authentication
 */
int libssh2_userauth_keyboard_interactive_ex(
    LIBSSH2_SESSION *session,
    const char *username, unsigned int username_len,
    LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC(*response_callback))
{
    int rc;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    BLOCK_ADJUST(rc, session,
                 userauth_keyboard_interactive(session, username, username_len,
                                               response_callback));
    return rc;
}

/*
 * Authenticate using an external callback function
 */
int libssh2_userauth_publickey_sk(
    LIBSSH2_SESSION *session,
    const char *username, size_t username_len,
    const unsigned char *publickeydata, size_t publickeydata_len,
    const char *privkeyblob, size_t privkeyblob_len,
    const char *passphrase,
    LIBSSH2_USERAUTH_SK_SIGN_FUNC(*sign_callback),
    void **abstract)
{
    int rc = LIBSSH2_ERROR_NONE;

    char *tmp_method = NULL;
    size_t tmp_method_len = 0;

    unsigned char *tmp_publickeydata = NULL;
    size_t tmp_publickeydata_len = 0;

    unsigned char *pubkeydata = NULL;
    size_t pubkeydata_len = 0;

    LIBSSH2_PRIVKEY_SK sk_info = { 0 };
    void *sign_abstract = &sk_info;

    if(!session)
        return LIBSSH2_ERROR_BAD_USE;

    sk_info.sign_callback = sign_callback;
    sk_info.orig_abstract = abstract;

    if(privkeyblob_len && privkeyblob) {

        if(ssh2_sk_pubkey(session,
                          &tmp_method,
                          &tmp_method_len,
                          &tmp_publickeydata,
                          &tmp_publickeydata_len,
                          &sk_info.algorithm,
                          &sk_info.flags,
                          &sk_info.application,
                          &sk_info.key_handle,
                          &sk_info.handle_len,
                          NULL, privkeyblob, privkeyblob_len,
                          passphrase))
            return ssh2_err(session, LIBSSH2_ERROR_FILE,
                            "Unable to extract public key from private key.");
        else if(publickeydata_len == 0 || !publickeydata) {
            session->userauth_pblc_method = tmp_method;
            session->userauth_pblc_method_len = tmp_method_len;

            pubkeydata_len = tmp_publickeydata_len;
            pubkeydata = tmp_publickeydata;
        }
        else {
            if(tmp_method)
                SSH2_FREE(session, tmp_method);

            rc = userauth_read_pubkey(session,
                                      &session->userauth_pblc_method,
                                      &session->userauth_pblc_method_len,
                                      &pubkeydata, &pubkeydata_len,
                                      NULL,
                                      (const char *)publickeydata,
                                      publickeydata_len);
        }
    }
    else
        return ssh2_err(session, LIBSSH2_ERROR_FILE,
                        "Invalid data in public and private key.");

    if(rc == LIBSSH2_ERROR_NONE) {
        rc = ssh2_userauth_publickey(session, username, username_len,
                                     pubkeydata, pubkeydata_len,
                                     libssh2_sign_sk, &sign_abstract);

        while(rc == LIBSSH2_ERROR_EAGAIN)
            rc = ssh2_userauth_publickey(session, username, username_len,
                                         pubkeydata, pubkeydata_len,
                                         libssh2_sign_sk, &sign_abstract);
    }

    if(tmp_publickeydata)
        SSH2_FREE(session, tmp_publickeydata);
    if(sk_info.application)
        SSH2_FREE(session, SSH2_UNCONST(sk_info.application));

    return rc;
}
