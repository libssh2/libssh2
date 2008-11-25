/* Copyright (c) 2004-2007, Sara Golemon <sarag@libssh2.org>
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

#include <ctype.h>
#include <stdio.h>

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif


/* {{{ proto libssh2_userauth_list
 * List authentication methods
 * Will yield successful login if "none" happens to be allowable for this user
 * Not a common configuration for any SSH server though
 * username should be NULL, or a null terminated string
 */
LIBSSH2_API char *
libssh2_userauth_list(LIBSSH2_SESSION * session, const char *username,
                      unsigned int username_len)
{
    static const unsigned char reply_codes[3] =
        { SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, 0 };
    /* packet_type(1) + username_len(4) + service_len(4) +
       service(14)"ssh-connection" + method_len(4) + method(4)"none" */
    unsigned long methods_len;
    unsigned char *s;
    int rc;

    if (session->userauth_list_state == libssh2_NB_state_idle) {
        /* Zero the whole thing out */
        memset(&session->userauth_list_packet_requirev_state, 0,
               sizeof(session->userauth_list_packet_requirev_state));

        session->userauth_list_data_len = username_len + 31;

        s = session->userauth_list_data =
            LIBSSH2_ALLOC(session, session->userauth_list_data_len);
        if (!session->userauth_list_data) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for userauth_list", 0);
            return NULL;
        }

        *(s++) = SSH_MSG_USERAUTH_REQUEST;
        libssh2_htonu32(s, username_len);
        s += 4;
        if (username) {
            memcpy(s, username, username_len);
            s += username_len;
        }

        libssh2_htonu32(s, 14);
        s += 4;
        memcpy(s, "ssh-connection", 14);
        s += 14;

        libssh2_htonu32(s, 4);
        s += 4;
        memcpy(s, "none", 4);
        s += 4;

        session->userauth_list_state = libssh2_NB_state_created;
    }

    if (session->userauth_list_state == libssh2_NB_state_created) {
        rc = libssh2_packet_write(session, session->userauth_list_data,
                                  session->userauth_list_data_len);
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block requesting userauth list", 0);
            return NULL;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send userauth-none request", 0);
            LIBSSH2_FREE(session, session->userauth_list_data);
            session->userauth_list_data = NULL;
            session->userauth_list_state = libssh2_NB_state_idle;
            return NULL;
        }
        LIBSSH2_FREE(session, session->userauth_list_data);
        session->userauth_list_data = NULL;

        session->userauth_list_state = libssh2_NB_state_sent;
    }

    if (session->userauth_list_state == libssh2_NB_state_sent) {
        rc = libssh2_packet_requirev_ex(session, reply_codes,
                                        &session->userauth_list_data,
                                        &session->userauth_list_data_len, 0,
                                        NULL, 0,
                                        &session->
                                        userauth_list_packet_requirev_state);
        if (rc == PACKET_EAGAIN) {
            libssh2_error(session, LIBSSH2_ERROR_EAGAIN,
                          "Would block requesting userauth list", 0);
            return NULL;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_NONE, "No error", 0);
            session->userauth_list_state = libssh2_NB_state_idle;
            return NULL;
        }

        if (session->userauth_list_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
            /* Wow, who'dve thought... */
            libssh2_error(session, LIBSSH2_ERROR_NONE, "No error", 0);
            LIBSSH2_FREE(session, session->userauth_list_data);
            session->userauth_list_data = NULL;
            session->state |= LIBSSH2_STATE_AUTHENTICATED;
            session->userauth_list_state = libssh2_NB_state_idle;
            return NULL;
        }

        methods_len = libssh2_ntohu32(session->userauth_list_data + 1);

        /* Do note that the memory areas overlap! */
        memmove(session->userauth_list_data, session->userauth_list_data + 5,
               methods_len);
        session->userauth_list_data[methods_len] = '\0';
        _libssh2_debug(session, LIBSSH2_DBG_AUTH, "Permitted auth methods: %s",
                       session->userauth_list_data);
    }

    session->userauth_list_state = libssh2_NB_state_idle;
    return (char *) session->userauth_list_data;
}

/* }}} */

/* {{{ libssh2_userauth_authenticated
 * 0 if not yet authenticated
 * non-zero is already authenticated
 */
LIBSSH2_API int
libssh2_userauth_authenticated(LIBSSH2_SESSION * session)
{
    return session->state & LIBSSH2_STATE_AUTHENTICATED;
}

/* }}} */

/* {{{ libssh2_userauth_password
 * Plain ol' login
 */
LIBSSH2_API int
libssh2_userauth_password_ex(LIBSSH2_SESSION * session, const char *username,
                             unsigned int username_len, const char *password,
                             unsigned int password_len,
                             LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb)))
{
    unsigned char *s;
    static const unsigned char reply_codes[4] =
        { SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE,
        SSH_MSG_USERAUTH_PASSWD_CHANGEREQ, 0
    };
    int rc;

    if (session->userauth_pswd_state == libssh2_NB_state_idle) {
        /* Zero the whole thing out */
        memset(&session->userauth_pswd_packet_requirev_state, 0,
               sizeof(session->userauth_pswd_packet_requirev_state));

        /*
         * 40 = acket_type(1) + username_len(4) + service_len(4) + 
         * service(14)"ssh-connection" + method_len(4) + method(8)"password" +
         * chgpwdbool(1) + password_len(4) */
        session->userauth_pswd_data_len = username_len + password_len + 40;

        session->userauth_pswd_data0 = ~SSH_MSG_USERAUTH_PASSWD_CHANGEREQ;

        s = session->userauth_pswd_data =
            LIBSSH2_ALLOC(session, session->userauth_pswd_data_len);
        if (!session->userauth_pswd_data) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for userauth-password request",
                          0);
            return -1;
        }

        *(s++) = SSH_MSG_USERAUTH_REQUEST;
        libssh2_htonu32(s, username_len);
        s += 4;
        memcpy(s, username, username_len);
        s += username_len;

        libssh2_htonu32(s, sizeof("ssh-connection") - 1);
        s += 4;
        memcpy(s, "ssh-connection", sizeof("ssh-connection") - 1);
        s += sizeof("ssh-connection") - 1;

        libssh2_htonu32(s, sizeof("password") - 1);
        s += 4;
        memcpy(s, "password", sizeof("password") - 1);
        s += sizeof("password") - 1;

        *s = '\0';
        s++;

        libssh2_htonu32(s, password_len);
        s += 4;
        memcpy(s, password, password_len);
        s += password_len;

        _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                       "Attempting to login using password authentication");

        session->userauth_pswd_state = libssh2_NB_state_created;
    }

    if (session->userauth_pswd_state == libssh2_NB_state_created) {
        rc = libssh2_packet_write(session, session->userauth_pswd_data,
                                  session->userauth_pswd_data_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send userauth-password request", 0);
            LIBSSH2_FREE(session, session->userauth_pswd_data);
            session->userauth_pswd_data = NULL;
            session->userauth_pswd_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, session->userauth_pswd_data);
        session->userauth_pswd_data = NULL;

        session->userauth_pswd_state = libssh2_NB_state_sent;
    }

  password_response:

    if ((session->userauth_pswd_state == libssh2_NB_state_sent)
        || (session->userauth_pswd_state == libssh2_NB_state_sent1)
        || (session->userauth_pswd_state == libssh2_NB_state_sent2)) {
        if (session->userauth_pswd_state == libssh2_NB_state_sent) {
            rc = libssh2_packet_requirev_ex(session, reply_codes,
                                            &session->userauth_pswd_data,
                                            &session->userauth_pswd_data_len,
                                            0, NULL, 0,
                                            &session->
                                            userauth_pswd_packet_requirev_state);
            if (rc == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            } else if (rc) {
                session->userauth_pswd_state = libssh2_NB_state_idle;
                return -1;
            }

            if (session->userauth_pswd_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
                _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                               "Password authentication successful");
                LIBSSH2_FREE(session, session->userauth_pswd_data);
                session->userauth_pswd_data = NULL;
                session->state |= LIBSSH2_STATE_AUTHENTICATED;
                session->userauth_pswd_state = libssh2_NB_state_idle;
                return 0;
            }

            session->userauth_pswd_newpw = NULL;
            session->userauth_pswd_newpw_len = 0;

            session->userauth_pswd_state = libssh2_NB_state_sent1;
        }

        if ((session->userauth_pswd_data[0] ==
             SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
            || (session->userauth_pswd_data0 ==
                SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)) {
            session->userauth_pswd_data0 = SSH_MSG_USERAUTH_PASSWD_CHANGEREQ;

            if ((session->userauth_pswd_state == libssh2_NB_state_sent1) ||
                (session->userauth_pswd_state == libssh2_NB_state_sent2)) {
                if (session->userauth_pswd_state == libssh2_NB_state_sent1) {
                    _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                                   "Password change required");
                    LIBSSH2_FREE(session, session->userauth_pswd_data);
                    session->userauth_pswd_data = NULL;
                }
                if (passwd_change_cb) {
                    if (session->userauth_pswd_state == libssh2_NB_state_sent1) {
                        passwd_change_cb(session,
                                         &session->userauth_pswd_newpw,
                                         &session->userauth_pswd_newpw_len,
                                         &session->abstract);
                        if (!session->userauth_pswd_newpw) {
                            libssh2_error(session,
                                          LIBSSH2_ERROR_PASSWORD_EXPIRED,
                                          "Password expired, and callback failed",
                                          0);
                            return -1;
                        }

                        /* basic data_len + newpw_len(4) */
                        session->userauth_pswd_data_len =
                            username_len + password_len + 44 +
                            session->userauth_pswd_newpw_len;

                        s = session->userauth_pswd_data =
                            LIBSSH2_ALLOC(session,
                                          session->userauth_pswd_data_len);
                        if (!session->userauth_pswd_data) {
                            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                          "Unable to allocate memory for userauth-password-change request",
                                          0);
                            LIBSSH2_FREE(session,
                                         session->userauth_pswd_newpw);
                            session->userauth_pswd_newpw = NULL;
                            return -1;
                        }

                        *(s++) = SSH_MSG_USERAUTH_REQUEST;
                        libssh2_htonu32(s, username_len);
                        s += 4;
                        memcpy(s, username, username_len);
                        s += username_len;

                        libssh2_htonu32(s, sizeof("ssh-connection") - 1);
                        s += 4;
                        memcpy(s, "ssh-connection",
                               sizeof("ssh-connection") - 1);
                        s += sizeof("ssh-connection") - 1;

                        libssh2_htonu32(s, sizeof("password") - 1);
                        s += 4;
                        memcpy(s, "password", sizeof("password") - 1);
                        s += sizeof("password") - 1;

                        *s = 0x01;
                        s++;

                        libssh2_htonu32(s, password_len);
                        s += 4;
                        memcpy(s, password, password_len);
                        s += password_len;

                        libssh2_htonu32(s, session->userauth_pswd_newpw_len);
                        s += 4;
                        memcpy(s, session->userauth_pswd_newpw,
                               session->userauth_pswd_newpw_len);
                        s += session->userauth_pswd_newpw_len;

                        session->userauth_pswd_state = libssh2_NB_state_sent2;
                    }

                    if (session->userauth_pswd_state == libssh2_NB_state_sent2) {
                        rc = libssh2_packet_write(session,
                                                  session->userauth_pswd_data,
                                                  session->
                                                  userauth_pswd_data_len);
                        if (rc == PACKET_EAGAIN) {
                            return PACKET_EAGAIN;
                        } else if (rc) {
                            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                                          "Unable to send userauth-password-change request",
                                          0);
                            LIBSSH2_FREE(session, session->userauth_pswd_data);
                            session->userauth_pswd_data = NULL;
                            LIBSSH2_FREE(session,
                                         session->userauth_pswd_newpw);
                            session->userauth_pswd_newpw = NULL;
                            return -1;
                        }
                        LIBSSH2_FREE(session, session->userauth_pswd_data);
                        session->userauth_pswd_data = NULL;
                        LIBSSH2_FREE(session, session->userauth_pswd_newpw);
                        session->userauth_pswd_newpw = NULL;

                        /*
                         * Ugliest use of goto ever.  Blame it on the
                         * askN => requirev migration.
                         */
                        session->userauth_pswd_state = libssh2_NB_state_sent;
                        goto password_response;
                    }
                }
            } else {
                libssh2_error(session, LIBSSH2_ERROR_PASSWORD_EXPIRED,
                              "Password Expired, and no callback specified",
                              0);
                session->userauth_pswd_state = libssh2_NB_state_idle;
                return -1;
            }
        }
    }

    /* FAILURE */
    LIBSSH2_FREE(session, session->userauth_pswd_data);
    session->userauth_pswd_data = NULL;
    session->userauth_pswd_state = libssh2_NB_state_idle;
    return -1;
}

/* }}} */

/* {{{ libssh2_file_read_publickey
 * Read a public key from an id_???.pub style file
 */
static int
libssh2_file_read_publickey(LIBSSH2_SESSION * session, unsigned char **method,
                            unsigned long *method_len,
                            unsigned char **pubkeydata,
                            unsigned long *pubkeydata_len,
                            const char *pubkeyfile)
{
    FILE *fd;
    char c;
    unsigned char *pubkey = NULL, *sp1, *sp2, *tmp;
    size_t pubkey_len = 0;
    unsigned int tmp_len;

    _libssh2_debug(session, LIBSSH2_DBG_AUTH, "Loading public key file: %s",
                   pubkeyfile);
    /* Read Public Key */
    fd = fopen(pubkeyfile, "r");
    if (!fd) {
        libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to open public key file", 0);
        return -1;
    }
    while (!feof(fd) && (c = fgetc(fd)) != '\r' && c != '\n')
        pubkey_len++;
    if (feof(fd)) {
        /* the last character was EOF */
        pubkey_len--;
    }
    rewind(fd);

    if (pubkey_len <= 1) {
        libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid data in public key file", 0);
        fclose(fd);
        return -1;
    }

    pubkey = LIBSSH2_ALLOC(session, pubkey_len);
    if (!pubkey) {
        libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                      "Unable to allocate memory for public key data", 0);
        fclose(fd);
        return -1;
    }
    if (fread(pubkey, 1, pubkey_len, fd) != pubkey_len) {
        libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to read public key from file", 0);
        LIBSSH2_FREE(session, pubkey);
        fclose(fd);
        return -1;
    }
    fclose(fd);
    /*
     * Remove trailing whitespace
     */
    while (pubkey_len && isspace(pubkey[pubkey_len - 1]))
        pubkey_len--;

    if (!pubkey_len) {
        libssh2_error(session, LIBSSH2_ERROR_FILE, "Missing public key data",
                      0);
        LIBSSH2_FREE(session, pubkey);
        return -1;
    }

    if ((sp1 = memchr(pubkey, ' ', pubkey_len)) == NULL) {
        libssh2_error(session, LIBSSH2_ERROR_FILE, "Invalid public key data",
                      0);
        LIBSSH2_FREE(session, pubkey);
        return -1;
    }
    /* Wasting some bytes here (okay, more than some),
     * but since it's likely to be freed soon anyway, 
     * we'll just avoid the extra free/alloc and call it a wash */
    *method = pubkey;
    *method_len = sp1 - pubkey;

    sp1++;

    if ((sp2 = memchr(sp1, ' ', pubkey_len - *method_len)) == NULL) {
        /* Assume that the id string is missing, but that it's okay */
        sp2 = pubkey + pubkey_len;
    }

    if (libssh2_base64_decode
        (session, (char **) &tmp, &tmp_len, (char *) sp1, sp2 - sp1)) {
        libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Invalid key data, not base64 encoded", 0);
        LIBSSH2_FREE(session, pubkey);
        return -1;
    }
    *pubkeydata = tmp;
    *pubkeydata_len = tmp_len;

    return 0;
}

/* }}} */

/* {{{ libssh2_file_read_privatekey
 * Read a PEM encoded private key from an id_??? style file
 */
static int
libssh2_file_read_privatekey(LIBSSH2_SESSION * session,
                             const LIBSSH2_HOSTKEY_METHOD ** hostkey_method,
                             void **hostkey_abstract,
                             const unsigned char *method, int method_len,
                             const char *privkeyfile, const char *passphrase)
{
    const LIBSSH2_HOSTKEY_METHOD **hostkey_methods_avail =
        libssh2_hostkey_methods();

    _libssh2_debug(session, LIBSSH2_DBG_AUTH, "Loading private key file: %s",
                   privkeyfile);
    *hostkey_method = NULL;
    *hostkey_abstract = NULL;
    while (*hostkey_methods_avail && (*hostkey_methods_avail)->name) {
        if ((*hostkey_methods_avail)->initPEM
            && strncmp((*hostkey_methods_avail)->name, (const char *) method,
                       method_len) == 0) {
            *hostkey_method = *hostkey_methods_avail;
            break;
        }
        hostkey_methods_avail++;
    }
    if (!*hostkey_method) {
        libssh2_error(session, LIBSSH2_ERROR_METHOD_NONE,
                      "No handler for specified private key", 0);
        return -1;
    }

    if ((*hostkey_method)->
        initPEM(session, privkeyfile, (unsigned char *) passphrase,
                hostkey_abstract)) {
        libssh2_error(session, LIBSSH2_ERROR_FILE,
                      "Unable to initialize private key from file", 0);
        return -1;
    }

    return 0;
}

/* }}} */

/* {{{ libssh2_userauth_hostbased_fromfile_ex
 * Authenticate using a keypair found in the named files
 */
LIBSSH2_API int
libssh2_userauth_hostbased_fromfile_ex(LIBSSH2_SESSION * session,
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
    static const unsigned char reply_codes[3] =
        { SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE, 0 };
    int rc;

    if (session->userauth_host_state == libssh2_NB_state_idle) {
        const LIBSSH2_HOSTKEY_METHOD *privkeyobj;
        unsigned char *pubkeydata, *sig;
        unsigned long pubkeydata_len;
        unsigned long sig_len;
        void *abstract;
        unsigned char buf[5];
        struct iovec datavec[4];

        /* Zero the whole thing out */
        memset(&session->userauth_host_packet_requirev_state, 0,
               sizeof(session->userauth_host_packet_requirev_state));

        if (libssh2_file_read_publickey
            (session, &session->userauth_host_method,
             &session->userauth_host_method_len, &pubkeydata, &pubkeydata_len,
             publickey)) {
            return -1;
        }

        /*
         * 48 = packet_type(1) + username_len(4) + servicename_len(4) + 
         * service_name(14)"ssh-connection" + authmethod_len(4) +
         * authmethod(9)"hostbased" + method_len(4) + pubkeydata_len(4) + 
         * local_username_len(4)
         */
        session->userauth_host_packet_len =
            username_len + session->userauth_host_method_len + hostname_len +
            local_username_len + pubkeydata_len + 48;

        /*
         * Preallocate space for an overall length,  method name again,
         * and the signature, which won't be any larger than the size of 
         * the publickeydata itself
         */
        session->userauth_host_s = session->userauth_host_packet =
            LIBSSH2_ALLOC(session,
                          session->userauth_host_packet_len + 4 + (4 +
                                                                   session->
                                                                   userauth_host_method_len)
                          + (4 + pubkeydata_len));
        if (!session->userauth_host_packet) {
            LIBSSH2_FREE(session, session->userauth_host_method);
            session->userauth_host_method = NULL;
            return -1;
        }

        *(session->userauth_host_s++) = SSH_MSG_USERAUTH_REQUEST;
        libssh2_htonu32(session->userauth_host_s, username_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, username, username_len);
        session->userauth_host_s += username_len;

        libssh2_htonu32(session->userauth_host_s, 14);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, "ssh-connection", 14);
        session->userauth_host_s += 14;

        libssh2_htonu32(session->userauth_host_s, 9);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, "hostbased", 9);
        session->userauth_host_s += 9;

        libssh2_htonu32(session->userauth_host_s,
                        session->userauth_host_method_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, session->userauth_host_method,
               session->userauth_host_method_len);
        session->userauth_host_s += session->userauth_host_method_len;

        libssh2_htonu32(session->userauth_host_s, pubkeydata_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, pubkeydata, pubkeydata_len);
        session->userauth_host_s += pubkeydata_len;

        libssh2_htonu32(session->userauth_host_s, hostname_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, hostname, hostname_len);
        session->userauth_host_s += hostname_len;

        libssh2_htonu32(session->userauth_host_s, local_username_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, local_username, local_username_len);
        session->userauth_host_s += local_username_len;

        if (libssh2_file_read_privatekey
            (session, &privkeyobj, &abstract, session->userauth_host_method,
             session->userauth_host_method_len, privatekey, passphrase)) {
            LIBSSH2_FREE(session, session->userauth_host_method);
            session->userauth_host_method = NULL;
            LIBSSH2_FREE(session, session->userauth_host_packet);
            session->userauth_host_packet = NULL;
            return -1;
        }

        libssh2_htonu32(buf, session->session_id_len);
        datavec[0].iov_base = buf;
        datavec[0].iov_len = 4;
        datavec[1].iov_base = session->session_id;
        datavec[1].iov_len = session->session_id_len;
        datavec[2].iov_base = session->userauth_host_packet;
        datavec[2].iov_len = session->userauth_host_packet_len;

        if (privkeyobj->signv(session, &sig, &sig_len, 3, datavec, &abstract)) {
            LIBSSH2_FREE(session, session->userauth_host_method);
            session->userauth_host_method = NULL;
            LIBSSH2_FREE(session, session->userauth_host_packet);
            session->userauth_host_packet = NULL;
            if (privkeyobj->dtor) {
                privkeyobj->dtor(session, &abstract);
            }
            return -1;
        }

        if (privkeyobj->dtor) {
            privkeyobj->dtor(session, &abstract);
        }

        if (sig_len > pubkeydata_len) {
            unsigned char *newpacket;
            /* Should *NEVER* happen, but...well.. better safe than sorry */
            newpacket = LIBSSH2_REALLOC(session, session->userauth_host_packet, session->userauth_host_packet_len + 4 + (4 + session->userauth_host_method_len) + (4 + sig_len));       /* PK sigblob */
            if (!newpacket) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Failed allocating additional space for userauth-hostbased packet",
                              0);
                LIBSSH2_FREE(session, sig);
                LIBSSH2_FREE(session, session->userauth_host_packet);
                session->userauth_host_packet = NULL;
                LIBSSH2_FREE(session, session->userauth_host_method);
                session->userauth_host_method = NULL;
                return -1;
            }
            session->userauth_host_packet = newpacket;
        }

        session->userauth_host_s =
            session->userauth_host_packet + session->userauth_host_packet_len;

        libssh2_htonu32(session->userauth_host_s,
                        4 + session->userauth_host_method_len + 4 + sig_len);
        session->userauth_host_s += 4;

        libssh2_htonu32(session->userauth_host_s,
                        session->userauth_host_method_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, session->userauth_host_method,
               session->userauth_host_method_len);
        session->userauth_host_s += session->userauth_host_method_len;
        LIBSSH2_FREE(session, session->userauth_host_method);
        session->userauth_host_method = NULL;

        libssh2_htonu32(session->userauth_host_s, sig_len);
        session->userauth_host_s += 4;
        memcpy(session->userauth_host_s, sig, sig_len);
        session->userauth_host_s += sig_len;
        LIBSSH2_FREE(session, sig);

        _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                       "Attempting hostbased authentication");

        session->userauth_host_state = libssh2_NB_state_created;
    }

    if (session->userauth_host_state == libssh2_NB_state_created) {
        rc = libssh2_packet_write(session, session->userauth_host_packet,
                                  session->userauth_host_s -
                                  session->userauth_host_packet);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send userauth-hostbased request", 0);
            LIBSSH2_FREE(session, session->userauth_host_packet);
            session->userauth_host_packet = NULL;
            session->userauth_host_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, session->userauth_host_packet);
        session->userauth_host_packet = NULL;

        session->userauth_host_state = libssh2_NB_state_sent;
    }

    if (session->userauth_host_state == libssh2_NB_state_sent) {
        unsigned long data_len;
        rc = libssh2_packet_requirev_ex(session, reply_codes,
                                        &session->userauth_host_data,
                                        &data_len, 0, NULL, 0,
                                        &session->
                                        userauth_host_packet_requirev_state);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            session->userauth_host_state = libssh2_NB_state_idle;
            return -1;
        }

        if (session->userauth_host_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
            _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                           "Hostbased authentication successful");
            /* We are us and we've proved it. */
            LIBSSH2_FREE(session, session->userauth_host_data);
            session->userauth_host_data = NULL;
            session->state |= LIBSSH2_STATE_AUTHENTICATED;
            session->userauth_host_state = libssh2_NB_state_idle;
            return 0;
        }
    }

    /* This public key is not allowed for this user on this server */
    LIBSSH2_FREE(session, session->userauth_host_data);
    session->userauth_host_data = NULL;
    libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                  "Invalid signature for supplied public key, or bad username/public key combination",
                  0);
    session->userauth_host_state = libssh2_NB_state_idle;
    return -1;
}

/* }}} */

/* {{{ libssh2_userauth_publickey_fromfile_ex
 * Authenticate using a keypair found in the named files
 */
LIBSSH2_API int
libssh2_userauth_publickey_fromfile_ex(LIBSSH2_SESSION * session,
                                       const char *username,
                                       unsigned int username_len,
                                       const char *publickey,
                                       const char *privatekey,
                                       const char *passphrase)
{
    unsigned long pubkeydata_len = 0;
    unsigned char reply_codes[4] =
        { SSH_MSG_USERAUTH_SUCCESS, SSH_MSG_USERAUTH_FAILURE,
        SSH_MSG_USERAUTH_PK_OK, 0
    };
    int rc;

    if (session->userauth_pblc_state == libssh2_NB_state_idle) {
        unsigned char *pubkeydata;

        /* Zero the whole thing out */
        memset(&session->userauth_pblc_packet_requirev_state, 0,
               sizeof(session->userauth_pblc_packet_requirev_state));

        if (libssh2_file_read_publickey
            (session, &session->userauth_pblc_method,
             &session->userauth_pblc_method_len, &pubkeydata, &pubkeydata_len,
             publickey)) {
            return -1;
        }

        /*
         * 45 = packet_type(1) + username_len(4) + servicename_len(4) + 
         * service_name(14)"ssh-connection" + authmethod_len(4) + 
         * authmethod(9)"publickey" + sig_included(1)'\0' + algmethod_len(4) +
         * publickey_len(4)
         */
        session->userauth_pblc_packet_len =
            username_len + session->userauth_pblc_method_len + pubkeydata_len +
            45;

        /*
         * Preallocate space for an overall length,  method name again, and
         * the signature, which won't be any larger than the size of the 
         * publickeydata itself
         */
        session->userauth_pblc_s = session->userauth_pblc_packet =
            LIBSSH2_ALLOC(session,
                          session->userauth_pblc_packet_len + 4 + (4 +
                                                                   session->
                                                                   userauth_pblc_method_len)
                          + (4 + pubkeydata_len));
        if (!session->userauth_pblc_packet) {
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            LIBSSH2_FREE(session, pubkeydata);
            return -1;
        }

        *(session->userauth_pblc_s++) = SSH_MSG_USERAUTH_REQUEST;
        libssh2_htonu32(session->userauth_pblc_s, username_len);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, username, username_len);
        session->userauth_pblc_s += username_len;

        libssh2_htonu32(session->userauth_pblc_s, 14);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, "ssh-connection", 14);
        session->userauth_pblc_s += 14;

        libssh2_htonu32(session->userauth_pblc_s, 9);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, "publickey", 9);
        session->userauth_pblc_s += 9;

        session->userauth_pblc_b = session->userauth_pblc_s;
        /* Not sending signature with *this* packet */
        *(session->userauth_pblc_s++) = 0;

        libssh2_htonu32(session->userauth_pblc_s,
                        session->userauth_pblc_method_len);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, session->userauth_pblc_method,
               session->userauth_pblc_method_len);
        session->userauth_pblc_s += session->userauth_pblc_method_len;

        libssh2_htonu32(session->userauth_pblc_s, pubkeydata_len);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, pubkeydata, pubkeydata_len);
        session->userauth_pblc_s += pubkeydata_len;
        LIBSSH2_FREE(session, pubkeydata);

        _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                       "Attempting publickey authentication");

        session->userauth_pblc_state = libssh2_NB_state_created;
    }

    if (session->userauth_pblc_state == libssh2_NB_state_created) {
        rc = libssh2_packet_write(session, session->userauth_pblc_packet,
                                  session->userauth_pblc_packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send userauth-publickey request", 0);
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return -1;
        }

        session->userauth_pblc_state = libssh2_NB_state_sent;
    }

    if (session->userauth_pblc_state == libssh2_NB_state_sent) {
        const LIBSSH2_HOSTKEY_METHOD *privkeyobj;
        void *abstract;
        unsigned char buf[5];
        struct iovec datavec[4];
        unsigned char *sig;
        unsigned long sig_len;

        rc = libssh2_packet_requirev_ex(session, reply_codes,
                                        &session->userauth_pblc_data,
                                        &session->userauth_pblc_data_len, 0,
                                        NULL, 0,
                                        &session->
                                        userauth_pblc_packet_requirev_state);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return -1;
        }

        if (session->userauth_pblc_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
            _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                           "Pubkey authentication prematurely successful");
            /*
             * God help any SSH server that allows an UNVERIFIED
             * public key to validate the user
             */
            LIBSSH2_FREE(session, session->userauth_pblc_data);
            session->userauth_pblc_data = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            session->state |= LIBSSH2_STATE_AUTHENTICATED;
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return 0;
        }

        if (session->userauth_pblc_data[0] == SSH_MSG_USERAUTH_FAILURE) {
            /* This public key is not allowed for this user on this server */
            LIBSSH2_FREE(session, session->userauth_pblc_data);
            session->userauth_pblc_data = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_UNRECOGNIZED,
                          "Username/PublicKey combination invalid", 0);
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return -1;
        }

        /* Semi-Success! */
        LIBSSH2_FREE(session, session->userauth_pblc_data);
        session->userauth_pblc_data = NULL;

        if (libssh2_file_read_privatekey
            (session, &privkeyobj, &abstract, session->userauth_pblc_method,
             session->userauth_pblc_method_len, privatekey, passphrase)) {
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return -1;
        }

        *session->userauth_pblc_b = 0x01;

        libssh2_htonu32(buf, session->session_id_len);
        datavec[0].iov_base = buf;
        datavec[0].iov_len = 4;
        datavec[1].iov_base = session->session_id;
        datavec[1].iov_len = session->session_id_len;
        datavec[2].iov_base = session->userauth_pblc_packet;
        datavec[2].iov_len = session->userauth_pblc_packet_len;

        if (privkeyobj->signv(session, &sig, &sig_len, 3, datavec, &abstract)) {
            LIBSSH2_FREE(session, session->userauth_pblc_method);
            session->userauth_pblc_method = NULL;
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            if (privkeyobj->dtor) {
                privkeyobj->dtor(session, &abstract);
            }
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return -1;
        }

        if (privkeyobj->dtor) {
            privkeyobj->dtor(session, &abstract);
        }

	/* 
	 * If this function was restarted, pubkeydata_len might still be 0
	 * which will cause an unnecessary but harmless realloc here.
	 */
        if (sig_len > pubkeydata_len) {
            unsigned char *newpacket;
            /* Should *NEVER* happen, but...well.. better safe than sorry */
            newpacket = LIBSSH2_REALLOC(session, session->userauth_pblc_packet, session->userauth_pblc_packet_len + 4 + (4 + session->userauth_pblc_method_len) + (4 + sig_len));       /* PK sigblob */
            if (!newpacket) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Failed allocating additional space for userauth-publickey packet",
                              0);
                LIBSSH2_FREE(session, sig);
                LIBSSH2_FREE(session, session->userauth_pblc_packet);
                session->userauth_pblc_packet = NULL;
                LIBSSH2_FREE(session, session->userauth_pblc_method);
                session->userauth_pblc_method = NULL;
                session->userauth_pblc_state = libssh2_NB_state_idle;
                return -1;
            }
            session->userauth_pblc_packet = newpacket;
        }

        session->userauth_pblc_s =
            session->userauth_pblc_packet + session->userauth_pblc_packet_len;
        session->userauth_pblc_b = NULL;

        libssh2_htonu32(session->userauth_pblc_s,
                        4 + session->userauth_pblc_method_len + 4 + sig_len);
        session->userauth_pblc_s += 4;

        libssh2_htonu32(session->userauth_pblc_s,
                        session->userauth_pblc_method_len);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, session->userauth_pblc_method,
               session->userauth_pblc_method_len);
        session->userauth_pblc_s += session->userauth_pblc_method_len;
        LIBSSH2_FREE(session, session->userauth_pblc_method);
        session->userauth_pblc_method = NULL;

        libssh2_htonu32(session->userauth_pblc_s, sig_len);
        session->userauth_pblc_s += 4;
        memcpy(session->userauth_pblc_s, sig, sig_len);
        session->userauth_pblc_s += sig_len;
        LIBSSH2_FREE(session, sig);

        _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                       "Attempting publickey authentication -- phase 2");

        session->userauth_pblc_state = libssh2_NB_state_sent1;
    }

    if (session->userauth_pblc_state == libssh2_NB_state_sent1) {
        rc = libssh2_packet_write(session, session->userauth_pblc_packet,
                                  session->userauth_pblc_s -
                                  session->userauth_pblc_packet);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send userauth-publickey request", 0);
            LIBSSH2_FREE(session, session->userauth_pblc_packet);
            session->userauth_pblc_packet = NULL;
            session->userauth_pblc_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, session->userauth_pblc_packet);
        session->userauth_pblc_packet = NULL;

        session->userauth_pblc_state = libssh2_NB_state_sent2;
    }

    /* PK_OK is no longer valid */
    reply_codes[2] = 0;

    rc = libssh2_packet_requirev_ex(session, reply_codes,
                                    &session->userauth_pblc_data,
                                    &session->userauth_pblc_data_len, 0, NULL,
                                    0,
                                    &session->
                                    userauth_pblc_packet_requirev_state);
    if (rc == PACKET_EAGAIN) {
        return PACKET_EAGAIN;
    } else if (rc) {
        session->userauth_pblc_state = libssh2_NB_state_idle;
        return -1;
    }

    if (session->userauth_pblc_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
        _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                       "Publickey authentication successful");
        /* We are us and we've proved it. */
        LIBSSH2_FREE(session, session->userauth_pblc_data);
        session->userauth_pblc_data = NULL;
        session->state |= LIBSSH2_STATE_AUTHENTICATED;
        session->userauth_pblc_state = libssh2_NB_state_idle;
        return 0;
    }

    /* This public key is not allowed for this user on this server */
    LIBSSH2_FREE(session, session->userauth_pblc_data);
    session->userauth_pblc_data = NULL;
    libssh2_error(session, LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED,
                  "Invalid signature for supplied public key, or bad username/public key combination",
                  0);
    session->userauth_pblc_state = libssh2_NB_state_idle;
    return -1;
}

/* }}} */

/* {{{ libssh2_userauth_keyboard_interactive
 * Authenticate using a challenge-response authentication
 */
LIBSSH2_API int
libssh2_userauth_keyboard_interactive_ex(LIBSSH2_SESSION * session,
                                         const char *username,
                                         unsigned int username_len,
                                         LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC((*response_callback)))
{
    unsigned char *s;
    int rc;

    static const unsigned char reply_codes[4] = { SSH_MSG_USERAUTH_SUCCESS,
        SSH_MSG_USERAUTH_FAILURE, SSH_MSG_USERAUTH_INFO_REQUEST, 0
    };
    unsigned int language_tag_len;
    unsigned int i;

    if (session->userauth_kybd_state == libssh2_NB_state_idle) {
        session->userauth_kybd_auth_name = NULL;
        session->userauth_kybd_auth_instruction = NULL;
        session->userauth_kybd_num_prompts = 0;
        session->userauth_kybd_auth_failure = 1;
        session->userauth_kybd_prompts = NULL;
        session->userauth_kybd_responses = NULL;

        /* Zero the whole thing out */
        memset(&session->userauth_kybd_packet_requirev_state, 0,
               sizeof(session->userauth_kybd_packet_requirev_state));

        session->userauth_kybd_packet_len = 1   /* byte      SSH_MSG_USERAUTH_REQUEST */
            + 4 + username_len  /* string    user name (ISO-10646 UTF-8, as defined in [RFC-3629]) */
            + 4 + 14            /* string    service name (US-ASCII) */
            + 4 + 20            /* string    "keyboard-interactive" (US-ASCII) */
            + 4 + 0             /* string    language tag (as defined in [RFC-3066]) */
            + 4 + 0             /* string    submethods (ISO-10646 UTF-8) */
            ;

        session->userauth_kybd_data = s =
            LIBSSH2_ALLOC(session, session->userauth_kybd_packet_len);
        if (!s) {
            libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                          "Unable to allocate memory for keyboard-interactive authentication",
                          0);
            return -1;
        }

        *s++ = SSH_MSG_USERAUTH_REQUEST;

        /* user name */
        libssh2_htonu32(s, username_len);
        s += 4;
        memcpy(s, username, username_len);
        s += username_len;

        /* service name */
        libssh2_htonu32(s, sizeof("ssh-connection") - 1);
        s += 4;
        memcpy(s, "ssh-connection", sizeof("ssh-connection") - 1);
        s += sizeof("ssh-connection") - 1;

        /* "keyboard-interactive" */
        libssh2_htonu32(s, sizeof("keyboard-interactive") - 1);
        s += 4;
        memcpy(s, "keyboard-interactive", sizeof("keyboard-interactive") - 1);
        s += sizeof("keyboard-interactive") - 1;

        /* language tag */
        libssh2_htonu32(s, 0);
        s += 4;

        /* submethods */
        libssh2_htonu32(s, 0);
        s += 4;

        _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                       "Attempting keyboard-interactive authentication");

        session->userauth_kybd_state = libssh2_NB_state_created;
    }

    if (session->userauth_kybd_state == libssh2_NB_state_created) {
        rc = libssh2_packet_write(session, session->userauth_kybd_data,
                                  session->userauth_kybd_packet_len);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        } else if (rc) {
            libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                          "Unable to send keyboard-interactive request", 0);
            LIBSSH2_FREE(session, session->userauth_kybd_data);
            session->userauth_kybd_data = NULL;
            session->userauth_kybd_state = libssh2_NB_state_idle;
            return -1;
        }
        LIBSSH2_FREE(session, session->userauth_kybd_data);
        session->userauth_kybd_data = NULL;

        session->userauth_kybd_state = libssh2_NB_state_sent;
    }

    for(;;) {
        if (session->userauth_kybd_state == libssh2_NB_state_sent) {
            rc = libssh2_packet_requirev_ex(session, reply_codes,
                                            &session->userauth_kybd_data,
                                            &session->userauth_kybd_data_len,
                                            0, NULL, 0,
                                            &session->
                                            userauth_kybd_packet_requirev_state);
            if (rc == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            } else if (rc) {
                session->userauth_kybd_state = libssh2_NB_state_idle;
                return -1;
            }

            if (session->userauth_kybd_data[0] == SSH_MSG_USERAUTH_SUCCESS) {
                _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                               "Keyboard-interactive authentication successful");
                LIBSSH2_FREE(session, session->userauth_kybd_data);
                session->userauth_kybd_data = NULL;
                session->state |= LIBSSH2_STATE_AUTHENTICATED;
                session->userauth_kybd_state = libssh2_NB_state_idle;
                return 0;
            }

            if (session->userauth_kybd_data[0] == SSH_MSG_USERAUTH_FAILURE) {
                LIBSSH2_FREE(session, session->userauth_kybd_data);
                session->userauth_kybd_data = NULL;
                session->userauth_kybd_state = libssh2_NB_state_idle;
                return -1;
            }

            /* server requested PAM-like conversation */

            s = session->userauth_kybd_data + 1;

            /* string    name (ISO-10646 UTF-8) */
            session->userauth_kybd_auth_name_len = libssh2_ntohu32(s);
            s += 4;
            session->userauth_kybd_auth_name =
                LIBSSH2_ALLOC(session, session->userauth_kybd_auth_name_len);
            if (!session->userauth_kybd_auth_name) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate memory for keyboard-interactive 'name' request field",
                              0);
                goto cleanup;
            }
            memcpy(session->userauth_kybd_auth_name, s,
                   session->userauth_kybd_auth_name_len);
            s += session->userauth_kybd_auth_name_len;

            /* string    instruction (ISO-10646 UTF-8) */
            session->userauth_kybd_auth_instruction_len = libssh2_ntohu32(s);
            s += 4;
            session->userauth_kybd_auth_instruction =
                LIBSSH2_ALLOC(session,
                              session->userauth_kybd_auth_instruction_len);
            if (!session->userauth_kybd_auth_instruction) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate memory for keyboard-interactive 'instruction' request field",
                              0);
                goto cleanup;
            }
            memcpy(session->userauth_kybd_auth_instruction, s,
                   session->userauth_kybd_auth_instruction_len);
            s += session->userauth_kybd_auth_instruction_len;

            /* string    language tag (as defined in [RFC-3066]) */
            language_tag_len = libssh2_ntohu32(s);
            s += 4;
            /* ignoring this field as deprecated */
            s += language_tag_len;

            /* int       num-prompts */
            session->userauth_kybd_num_prompts = libssh2_ntohu32(s);
            s += 4;

            session->userauth_kybd_prompts =
                LIBSSH2_ALLOC(session,
                              sizeof(LIBSSH2_USERAUTH_KBDINT_PROMPT) *
                              session->userauth_kybd_num_prompts);
            if (!session->userauth_kybd_prompts) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate memory for keyboard-interactive prompts array",
                              0);
                goto cleanup;
            }
            memset(session->userauth_kybd_prompts, 0,
                   sizeof(LIBSSH2_USERAUTH_KBDINT_PROMPT) *
                   session->userauth_kybd_num_prompts);

            session->userauth_kybd_responses =
                LIBSSH2_ALLOC(session,
                              sizeof(LIBSSH2_USERAUTH_KBDINT_RESPONSE) *
                              session->userauth_kybd_num_prompts);
            if (!session->userauth_kybd_responses) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate memory for keyboard-interactive responses array",
                              0);
                goto cleanup;
            }
            memset(session->userauth_kybd_responses, 0,
                   sizeof(LIBSSH2_USERAUTH_KBDINT_RESPONSE) *
                   session->userauth_kybd_num_prompts);

            for(i = 0; i != session->userauth_kybd_num_prompts; ++i) {
                /* string    prompt[1] (ISO-10646 UTF-8) */
                session->userauth_kybd_prompts[i].length = libssh2_ntohu32(s);
                s += 4;
                session->userauth_kybd_prompts[i].text =
                    LIBSSH2_ALLOC(session,
                                  session->userauth_kybd_prompts[i].length);
                if (!session->userauth_kybd_prompts[i].text) {
                    libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                                  "Unable to allocate memory for keyboard-interactive prompt message",
                                  0);
                    goto cleanup;
                }
                memcpy(session->userauth_kybd_prompts[i].text, s,
                       session->userauth_kybd_prompts[i].length);
                s += session->userauth_kybd_prompts[i].length;

                /* boolean   echo[1] */
                session->userauth_kybd_prompts[i].echo = *s++;
            }

            response_callback(session->userauth_kybd_auth_name,
                              session->userauth_kybd_auth_name_len,
                              session->userauth_kybd_auth_instruction,
                              session->userauth_kybd_auth_instruction_len,
                              session->userauth_kybd_num_prompts,
                              session->userauth_kybd_prompts,
                              session->userauth_kybd_responses,
                              &session->abstract);

            _libssh2_debug(session, LIBSSH2_DBG_AUTH,
                           "Keyboard-interactive response callback function invoked");

            session->userauth_kybd_packet_len = 1       /* byte      SSH_MSG_USERAUTH_INFO_RESPONSE */
                + 4             /* int       num-responses */
                ;

            for(i = 0; i != session->userauth_kybd_num_prompts; ++i) {
                /* string    response[1] (ISO-10646 UTF-8) */
                session->userauth_kybd_packet_len +=
                    4 + session->userauth_kybd_responses[i].length;
            }

            session->userauth_kybd_data = s =
                LIBSSH2_ALLOC(session, session->userauth_kybd_packet_len);
            if (!s) {
                libssh2_error(session, LIBSSH2_ERROR_ALLOC,
                              "Unable to allocate memory for keyboard-interactive response packet",
                              0);
                goto cleanup;
            }

            *s = SSH_MSG_USERAUTH_INFO_RESPONSE;
            s++;
            libssh2_htonu32(s, session->userauth_kybd_num_prompts);
            s += 4;

            for(i = 0; i != session->userauth_kybd_num_prompts; ++i) {
                libssh2_htonu32(s, session->userauth_kybd_responses[i].length);
                s += 4;
                memcpy(s, session->userauth_kybd_responses[i].text,
                       session->userauth_kybd_responses[i].length);
                s += session->userauth_kybd_responses[i].length;
            }

            session->userauth_kybd_state = libssh2_NB_state_sent1;
        }

        if (session->userauth_kybd_state == libssh2_NB_state_sent1) {
            rc = libssh2_packet_write(session, session->userauth_kybd_data,
                                      session->userauth_kybd_packet_len);
            if (rc == PACKET_EAGAIN) {
                return PACKET_EAGAIN;
            }
            if (rc) {
                libssh2_error(session, LIBSSH2_ERROR_SOCKET_SEND,
                              "Unable to send userauth-keyboard-interactive request",
                              0);
                goto cleanup;
            }

            session->userauth_kybd_auth_failure = 0;
        }

      cleanup:
        /*
         * It's safe to clean all the data here, because unallocated pointers
         * are filled by zeroes
         */

        LIBSSH2_FREE(session, session->userauth_kybd_data);
        session->userauth_kybd_data = NULL;

        if (session->userauth_kybd_prompts) {
            for(i = 0; i != session->userauth_kybd_num_prompts; ++i) {
                LIBSSH2_FREE(session, session->userauth_kybd_prompts[i].text);
                session->userauth_kybd_prompts[i].text = NULL;
            }
        }

        if (session->userauth_kybd_responses) {
            for(i = 0; i != session->userauth_kybd_num_prompts; ++i) {
                LIBSSH2_FREE(session,
                             session->userauth_kybd_responses[i].text);
                session->userauth_kybd_responses[i].text = NULL;
            }
        }

        LIBSSH2_FREE(session, session->userauth_kybd_prompts);
        session->userauth_kybd_prompts = NULL;
        LIBSSH2_FREE(session, session->userauth_kybd_responses);
        session->userauth_kybd_responses = NULL;

        if (session->userauth_kybd_auth_failure) {
            session->userauth_kybd_state = libssh2_NB_state_idle;
            return -1;
        }

        session->userauth_kybd_state = libssh2_NB_state_sent;
    }
}

/* }}} */
