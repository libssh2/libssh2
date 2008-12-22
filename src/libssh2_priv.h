/* Copyright (c) 2004-2008, Sara Golemon <sarag@libssh2.org>
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

#ifndef LIBSSH2_PRIV_H
#define LIBSSH2_PRIV_H 1

#define LIBSSH2_LIBRARY
#include "libssh2_config.h"

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#include <stdio.h>
#include <time.h>

/* The following CPP block should really only be in session.c and
   packet.c.  However, AIX have #define's for 'events' and 'revents'
   and we are using those names in libssh2.h, so we need to include
   the AIX headers first, to make sure all code is compiled with
   consistent names of these fields.  While arguable the best would to
   change libssh2.h to use other names, that would break backwards
   compatibility.  For more information, see:
   http://www.mail-archive.com/libssh2-devel%40lists.sourceforge.net/msg00003.html
   http://www.mail-archive.com/libssh2-devel%40lists.sourceforge.net/msg00224.html
*/
#ifdef HAVE_POLL
# include <sys/poll.h>
#else
# if defined(HAVE_SELECT) && !defined(WIN32)
# ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
# else
# include <sys/time.h>
# include <sys/types.h>
# endif
# endif
#endif

#include "libssh2.h"
#include "libssh2_publickey.h"
#include "libssh2_sftp.h"

/* Provide iovec / writev on WIN32 platform. */
#ifdef WIN32

/* same as WSABUF */
struct iovec {
	u_long iov_len;
	char *iov_base;
};

#define inline __inline

static inline int writev(int sock, struct iovec *iov, int nvecs)
{
	DWORD ret;
	if (WSASend(sock, (LPWSABUF)iov, nvecs, &ret, 0, NULL, NULL) == 0) {
		return ret;
	}
	return -1;
}

#endif /* WIN32 */

/* Needed for struct iovec on some platforms */
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef LIBSSH2_LIBGCRYPT
#include "libgcrypt.h"
#else
#include "openssl.h"
#endif

#ifdef HAVE_WINSOCK2_H

#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>

#ifdef _MSC_VER
/* "inline" keyword is valid only with C++ engine! */
#define inline __inline
#endif

/* not really usleep, but safe for the way we use it in this lib */
static inline int usleep(int udelay)
{
	Sleep(udelay / 1000);
	return 0;
}

#endif

/* RFC4253 section 6.1 Maximum Packet Length says:
 *
 * "All implementations MUST be able to process packets with
 * uncompressed payload length of 32768 bytes or less and
 * total packet size of 35000 bytes or less (including length,
 * padding length, payload, padding, and MAC.)."
 */
#define MAX_SSH_PACKET_LEN 35000

#define LIBSSH2_ALLOC(session, count)                               session->alloc((count), &(session)->abstract)
#define LIBSSH2_REALLOC(session, ptr, count)                        ((ptr) ? session->realloc((ptr), (count), &(session)->abstract) : session->alloc((count), &(session)->abstract))
#define LIBSSH2_FREE(session, ptr)                                  session->free((ptr), &(session)->abstract)

#define LIBSSH2_IGNORE(session, data, datalen)                      session->ssh_msg_ignore((session), (data), (datalen), &(session)->abstract)
#define LIBSSH2_DEBUG(session, always_display, message, message_len, language, language_len)    \
                session->ssh_msg_disconnect((session), (always_display), (message), (message_len), (language), (language_len), &(session)->abstract)
#define LIBSSH2_DISCONNECT(session, reason, message, message_len, language, language_len)   \
                session->ssh_msg_disconnect((session), (reason), (message), (message_len), (language), (language_len), &(session)->abstract)

#define LIBSSH2_MACERROR(session, data, datalen)                    session->macerror((session), (data), (datalen), &(session)->abstract)
#define LIBSSH2_X11_OPEN(channel, shost, sport)                     channel->session->x11(((channel)->session), (channel), (shost), (sport), (&(channel)->session->abstract))

#define LIBSSH2_CHANNEL_CLOSE(session, channel)                     channel->close_cb((session), &(session)->abstract, (channel), &(channel)->abstract)

typedef struct _LIBSSH2_KEX_METHOD LIBSSH2_KEX_METHOD;
typedef struct _LIBSSH2_HOSTKEY_METHOD LIBSSH2_HOSTKEY_METHOD;
typedef struct _LIBSSH2_MAC_METHOD LIBSSH2_MAC_METHOD;
typedef struct _LIBSSH2_CRYPT_METHOD LIBSSH2_CRYPT_METHOD;
typedef struct _LIBSSH2_COMP_METHOD LIBSSH2_COMP_METHOD;

typedef struct _LIBSSH2_PACKET LIBSSH2_PACKET;
typedef struct _LIBSSH2_PACKET_BRIGADE LIBSSH2_PACKET_BRIGADE;
typedef struct _LIBSSH2_CHANNEL_BRIGADE LIBSSH2_CHANNEL_BRIGADE;

typedef int libssh2pack_t;

typedef enum
{
    libssh2_NB_state_idle = 0,
    libssh2_NB_state_allocated,
    libssh2_NB_state_created,
    libssh2_NB_state_sent,
    libssh2_NB_state_sent1,
    libssh2_NB_state_sent2,
    libssh2_NB_state_sent3,
    libssh2_NB_state_sent4,
    libssh2_NB_state_sent5,
    libssh2_NB_state_sent6,
    libssh2_NB_state_sent7,
    libssh2_NB_state_jump1,
    libssh2_NB_state_jump2,
    libssh2_NB_state_jump3
} libssh2_nonblocking_states;

typedef struct packet_require_state_t
{
    libssh2_nonblocking_states state;
    time_t start;
} packet_require_state_t;

typedef struct packet_requirev_state_t
{
    time_t start;
} packet_requirev_state_t;

typedef struct kmdhgGPsha1kex_state_t
{
    libssh2_nonblocking_states state;
    unsigned char *e_packet;
    unsigned char *s_packet;
    unsigned char *tmp;
    unsigned char h_sig_comp[SHA_DIGEST_LENGTH];
    unsigned char c;
    unsigned long e_packet_len;
    unsigned long s_packet_len;
    unsigned long tmp_len;
    _libssh2_bn_ctx *ctx;
    _libssh2_bn *x;
    _libssh2_bn *e;
    _libssh2_bn *f;
    _libssh2_bn *k;
    unsigned char *s;
    unsigned char *f_value;
    unsigned char *k_value;
    unsigned char *h_sig;
    unsigned long f_value_len;
    unsigned long k_value_len;
    unsigned long h_sig_len;
    libssh2_sha1_ctx exchange_hash;
    packet_require_state_t req_state;
    libssh2_nonblocking_states burn_state;
} kmdhgGPsha1kex_state_t;

typedef struct key_exchange_state_low_t
{
    libssh2_nonblocking_states state;
    packet_require_state_t req_state;
    kmdhgGPsha1kex_state_t exchange_state;
    _libssh2_bn *p;             /* SSH2 defined value (p_value) */
    _libssh2_bn *g;             /* SSH2 defined value (2) */
    unsigned char request[13];
    unsigned char *data;
    unsigned long request_len;
    unsigned long data_len;
} key_exchange_state_low_t;

typedef struct key_exchange_state_t
{
    libssh2_nonblocking_states state;
    packet_require_state_t req_state;
    key_exchange_state_low_t key_state_low;
    unsigned char *data;
    unsigned long data_len;
    unsigned char *oldlocal;
    unsigned long oldlocal_len;
} key_exchange_state_t;

#define FwdNotReq "Forward not requested"

typedef struct packet_queue_listener_state_t
{
    libssh2_nonblocking_states state;
    unsigned char packet[17 + (sizeof(FwdNotReq) - 1)];
    unsigned char *host;
    unsigned char *shost;
    uint32_t sender_channel;
    uint32_t initial_window_size;
    uint32_t packet_size;
    uint32_t port;
    uint32_t sport;
    uint32_t host_len;
    uint32_t shost_len;
} packet_queue_listener_state_t;

#define X11FwdUnAvil "X11 Forward Unavailable"

typedef struct packet_x11_open_state_t
{
    libssh2_nonblocking_states state;
    unsigned char packet[17 + (sizeof(X11FwdUnAvil) - 1)];
    unsigned char *shost;
    uint32_t sender_channel;
    uint32_t initial_window_size;
    uint32_t packet_size;
    uint32_t sport;
    uint32_t shost_len;
} packet_x11_open_state_t;

struct _LIBSSH2_PACKET
{
    unsigned char type;

    /* Unencrypted Payload (no type byte, no padding, just the facts ma'am) */
    unsigned char *data;
    unsigned long data_len;

    /* Where to start reading data from,
     * used for channel data that's been partially consumed */
    unsigned long data_head;

    /* Can the message be confirmed? */
    int mac;

    LIBSSH2_PACKET_BRIGADE *brigade;

    LIBSSH2_PACKET *next, *prev;
};

struct _LIBSSH2_PACKET_BRIGADE
{
    LIBSSH2_PACKET *head, *tail;
};

typedef struct _libssh2_channel_data
{
    /* Identifier */
    unsigned long id;

    /* Limits and restrictions */
    unsigned long window_size_initial, window_size, packet_size;

    /* Set to 1 when CHANNEL_CLOSE / CHANNEL_EOF sent/received */
    char close, eof, extended_data_ignore_mode;
} libssh2_channel_data;

struct _LIBSSH2_CHANNEL
{
    unsigned char *channel_type;
    unsigned channel_type_len;

    /* channel's program exit status */
    int exit_status;

    libssh2_channel_data local, remote;
    /* Amount of bytes to be refunded to receive window (but not yet sent) */
    unsigned long adjust_queue;

    LIBSSH2_SESSION *session;

    LIBSSH2_CHANNEL *next, *prev;

    void *abstract;
      LIBSSH2_CHANNEL_CLOSE_FUNC((*close_cb));

    /* State variables used in libssh2_channel_setenv_ex() */
    libssh2_nonblocking_states setenv_state;
    unsigned char *setenv_packet;
    unsigned long setenv_packet_len;
    unsigned char setenv_local_channel[4];
    packet_requirev_state_t setenv_packet_requirev_state;

    /* State variables used in libssh2_channel_request_pty_ex() */
    libssh2_nonblocking_states reqPTY_state;
    unsigned char *reqPTY_packet;
    unsigned long reqPTY_packet_len;
    unsigned char reqPTY_local_channel[4];
    packet_requirev_state_t reqPTY_packet_requirev_state;

    /* State variables used in libssh2_channel_x11_req_ex() */
    libssh2_nonblocking_states reqX11_state;
    unsigned char *reqX11_packet;
    unsigned long reqX11_packet_len;
    unsigned char reqX11_local_channel[4];
    packet_requirev_state_t reqX11_packet_requirev_state;

    /* State variables used in libssh2_channel_process_startup() */
    libssh2_nonblocking_states process_state;
    unsigned char *process_packet;
    unsigned long process_packet_len;
    unsigned char process_local_channel[4];
    packet_requirev_state_t process_packet_requirev_state;

    /* State variables used in libssh2_channel_flush_ex() */
    libssh2_nonblocking_states flush_state;
    unsigned long flush_refund_bytes;
    unsigned long flush_flush_bytes;

    /* State variables used in libssh2_channel_receive_window_adjust() */
    libssh2_nonblocking_states adjust_state;
    unsigned char adjust_adjust[9];     /* packet_type(1) + channel(4) + adjustment(4) */

    /* State variables used in libssh2_channel_read_ex() */
    libssh2_nonblocking_states read_state;
    LIBSSH2_PACKET *read_packet;
    LIBSSH2_PACKET *read_next;
    int read_block;
    int read_bytes_read;
    uint32_t read_local_id;
    int read_want;
    int read_unlink_packet;

    /* State variables used in libssh2_channel_write_ex() */
    libssh2_nonblocking_states write_state;
    unsigned char *write_packet;
    unsigned char *write_s;
    unsigned long write_packet_len;
    unsigned long write_bufwrote;
    size_t write_bufwrite;

    /* State variables used in libssh2_channel_close() */
    libssh2_nonblocking_states close_state;
    unsigned char close_packet[5];

    /* State variables used in libssh2_channel_wait_closedeof() */
    libssh2_nonblocking_states wait_eof_state;

    /* State variables used in libssh2_channel_wait_closed() */
    libssh2_nonblocking_states wait_closed_state;

    /* State variables used in libssh2_channel_free() */
    libssh2_nonblocking_states free_state;

    /* State variables used in libssh2_channel_handle_extended_data2() */
    libssh2_nonblocking_states extData2_state;
};

struct _LIBSSH2_CHANNEL_BRIGADE
{
    LIBSSH2_CHANNEL *head, *tail;
};

struct _LIBSSH2_LISTENER
{
    LIBSSH2_SESSION *session;

    char *host;
    int port;

    LIBSSH2_CHANNEL *queue;
    int queue_size;
    int queue_maxsize;

    LIBSSH2_LISTENER *prev, *next;

    /* State variables used in libssh2_channel_forward_cancel() */
    libssh2_nonblocking_states chanFwdCncl_state;
    unsigned char *chanFwdCncl_data;
    size_t chanFwdCncl_data_len;
};

typedef struct _libssh2_endpoint_data
{
    unsigned char *banner;

    unsigned char *kexinit;
    unsigned long kexinit_len;

    const LIBSSH2_CRYPT_METHOD *crypt;
    void *crypt_abstract;

    const LIBSSH2_MAC_METHOD *mac;
    unsigned long seqno;
    void *mac_abstract;

    const LIBSSH2_COMP_METHOD *comp;
    void *comp_abstract;

    /* Method Preferences -- NULL yields "load order" */
    char *crypt_prefs;
    char *mac_prefs;
    char *comp_prefs;
    char *lang_prefs;
} libssh2_endpoint_data;

#define PACKETBUFSIZE 4096

struct transportpacket
{
    /* ------------- for incoming data --------------- */
    unsigned char buf[PACKETBUFSIZE];
    unsigned char init[5];      /* first 5 bytes of the incoming data stream,
                                   still encrypted */
    int writeidx;               /* at what array index we do the next write into
                                   the buffer */
    int readidx;                /* at what array index we do the next read from
                                   the buffer */
    int packet_length;          /* the most recent packet_length as read from the
                                   network data */
    int padding_length;         /* the most recent padding_length as read from the
                                   network data */
    int data_num;               /* How much of the total package that has been read
                                   so far. */
    int total_num;              /* How much a total package is supposed to be, in
                                   number of bytes. A full package is
                                   packet_length + padding_length + 4 +
                                   mac_length. */
    unsigned char *payload;     /* this is a pointer to a LIBSSH2_ALLOC()
                                   area to which we write decrypted data */
    unsigned char *wptr;        /* write pointer into the payload to where we
                                   are currently writing decrypted data */

    /* ------------- for outgoing data --------------- */
    unsigned char *outbuf;      /* pointer to a LIBSSH2_ALLOC() area for the
                                   outgoing data */
    int ototal_num;             /* size of outbuf in number of bytes */
    unsigned char *odata;       /* original pointer to the data we stored in
                                   outbuf */
    unsigned long olen;         /* original size of the data we stored in
                                   outbuf */
    unsigned long osent;        /* number of bytes already sent */
};

struct _LIBSSH2_PUBLICKEY
{
    LIBSSH2_CHANNEL *channel;
    unsigned long version;

    /* State variables used in libssh2_publickey_packet_receive() */
    libssh2_nonblocking_states receive_state;
    unsigned char *receive_packet;
    unsigned long receive_packet_len;

    /* State variables used in libssh2_publickey_add_ex() */
    libssh2_nonblocking_states add_state;
    unsigned char *add_packet;
    unsigned char *add_s;

    /* State variables used in libssh2_publickey_remove_ex() */
    libssh2_nonblocking_states remove_state;
    unsigned char *remove_packet;
    unsigned char *remove_s;

    /* State variables used in libssh2_publickey_list_fetch() */
    libssh2_nonblocking_states listFetch_state;
    unsigned char *listFetch_s;
    unsigned char listFetch_buffer[12];
    unsigned char *listFetch_data;
    unsigned long listFetch_data_len;
};

#define SFTP_HANDLE_MAXLEN 256 /* according to spec! */

struct _LIBSSH2_SFTP_HANDLE
{
    LIBSSH2_SFTP *sftp;
    LIBSSH2_SFTP_HANDLE *prev, *next;

    /* This is a pre-allocated buffer used for sending SFTP requests as the
       whole thing might not get sent in one go. This buffer is used for read,
       write, close and MUST thus be big enough to suit all these. */
    unsigned char request_packet[SFTP_HANDLE_MAXLEN + 25];

    char handle[SFTP_HANDLE_MAXLEN];
    int handle_len;

    char handle_type;

    union _libssh2_sftp_handle_data
    {
        struct _libssh2_sftp_handle_file_data
        {
            libssh2_uint64_t offset;
        } file;
        struct _libssh2_sftp_handle_dir_data
        {
            unsigned long names_left;
            void *names_packet;
            char *next_name;
        } dir;
    } u;

    /* State variables used in libssh2_sftp_close_handle() */
    libssh2_nonblocking_states close_state;
    unsigned long close_request_id;
    unsigned char *close_packet;
};

struct _LIBSSH2_SFTP
{
    LIBSSH2_CHANNEL *channel;

    unsigned long request_id, version;

    LIBSSH2_PACKET_BRIGADE packets;

    LIBSSH2_SFTP_HANDLE *handles;

    unsigned long last_errno;

    /* Holder for partial packet, use in libssh2_sftp_packet_read() */
    unsigned char *partial_packet;      /* The data                */
    unsigned long partial_len;  /* Desired number of bytes */
    unsigned long partial_received;     /* Bytes received so far   */

    /* Time that libssh2_sftp_packet_requirev() started reading */
    time_t requirev_start;

    /* State variables used in libssh2_sftp_open_ex() */
    libssh2_nonblocking_states open_state;
    unsigned char *open_packet;
    ssize_t open_packet_len;
    unsigned long open_request_id;

    /* State variables used in libssh2_sftp_read() */
    libssh2_nonblocking_states read_state;
    unsigned char *read_packet;
    unsigned long read_request_id;
    size_t read_total_read;

    /* State variables used in libssh2_sftp_readdir() */
    libssh2_nonblocking_states readdir_state;
    unsigned char *readdir_packet;
    unsigned long readdir_request_id;

    /* State variables used in libssh2_sftp_write() */
    libssh2_nonblocking_states write_state;
    unsigned char *write_packet;
    unsigned long write_request_id;

    /* State variables used in libssh2_sftp_fstat_ex() */
    libssh2_nonblocking_states fstat_state;
    unsigned char *fstat_packet;
    unsigned long fstat_request_id;

    /* State variables used in libssh2_sftp_unlink_ex() */
    libssh2_nonblocking_states unlink_state;
    unsigned char *unlink_packet;
    unsigned long unlink_request_id;

    /* State variables used in libssh2_sftp_rename_ex() */
    libssh2_nonblocking_states rename_state;
    unsigned char *rename_packet;
    unsigned char *rename_s;
    unsigned long rename_request_id;

    /* State variables used in libssh2_sftp_mkdir() */
    libssh2_nonblocking_states mkdir_state;
    unsigned char *mkdir_packet;
    unsigned long mkdir_request_id;

    /* State variables used in libssh2_sftp_rmdir() */
    libssh2_nonblocking_states rmdir_state;
    unsigned char *rmdir_packet;
    unsigned long rmdir_request_id;

    /* State variables used in libssh2_sftp_stat() */
    libssh2_nonblocking_states stat_state;
    unsigned char *stat_packet;
    unsigned long stat_request_id;

    /* State variables used in libssh2_sftp_symlink() */
    libssh2_nonblocking_states symlink_state;
    unsigned char *symlink_packet;
    unsigned long symlink_request_id;
};

#define LIBSSH2_SCP_RESPONSE_BUFLEN     256

struct _LIBSSH2_SESSION
{
    /* Memory management callbacks */
    void *abstract;
      LIBSSH2_ALLOC_FUNC((*alloc));
      LIBSSH2_REALLOC_FUNC((*realloc));
      LIBSSH2_FREE_FUNC((*free));

    /* Other callbacks */
      LIBSSH2_IGNORE_FUNC((*ssh_msg_ignore));
      LIBSSH2_DEBUG_FUNC((*ssh_msg_debug));
      LIBSSH2_DISCONNECT_FUNC((*ssh_msg_disconnect));
      LIBSSH2_MACERROR_FUNC((*macerror));
      LIBSSH2_X11_OPEN_FUNC((*x11));

    /* Method preferences -- NULL yields "load order" */
    char *kex_prefs;
    char *hostkey_prefs;

    int state;
    int flags;

    /* Agreed Key Exchange Method */
    const LIBSSH2_KEX_METHOD *kex;
    int burn_optimistic_kexinit:1;

    unsigned char *session_id;
    unsigned long session_id_len;

    /* Server's public key */
    const LIBSSH2_HOSTKEY_METHOD *hostkey;
    void *server_hostkey_abstract;

    /* Either set with libssh2_session_hostkey() (for server mode)
     * Or read from server in (eg) KEXDH_INIT (for client mode)
     */
    unsigned char *server_hostkey;
    unsigned long server_hostkey_len;
#if LIBSSH2_MD5
    unsigned char server_hostkey_md5[MD5_DIGEST_LENGTH];
#endif                          /* ! LIBSSH2_MD5 */
    unsigned char server_hostkey_sha1[SHA_DIGEST_LENGTH];

    /* (remote as source of data -- packet_read ) */
    libssh2_endpoint_data remote;

    /* (local as source of data -- packet_write ) */
    libssh2_endpoint_data local;

    /* Inbound Data buffer -- Sometimes the packet that comes in isn't the packet we're ready for */
    LIBSSH2_PACKET_BRIGADE packets;

    /* Active connection channels */
    LIBSSH2_CHANNEL_BRIGADE channels;
    unsigned long next_channel;

    LIBSSH2_LISTENER *listeners;

    /* Actual I/O socket */
    int socket_fd;
    int socket_block;
    int socket_state;
    int socket_block_directions;

    /* Error tracking */
    char *err_msg;
    unsigned long err_msglen;
    int err_should_free;
    int err_code;

    /* struct members for packet-level reading */
    struct transportpacket packet;
#ifdef LIBSSH2DEBUG
    int showmask;               /* what debug/trace messages to display */
#endif

    /* State variables used in libssh2_banner_send() */
    libssh2_nonblocking_states banner_TxRx_state;
    char banner_TxRx_banner[256];
    ssize_t banner_TxRx_total_send;

    /* State variables used in libssh2_kexinit() */
    libssh2_nonblocking_states kexinit_state;
    unsigned char *kexinit_data;
    size_t kexinit_data_len;

    /* State variables used in libssh2_session_startup() */
    libssh2_nonblocking_states startup_state;
    unsigned char *startup_data;
    unsigned long startup_data_len;
    unsigned char startup_service[sizeof("ssh-userauth") + 5 - 1];
    unsigned long startup_service_length;
    packet_require_state_t startup_req_state;
    key_exchange_state_t startup_key_state;

    /* State variables used in libssh2_session_free() */
    libssh2_nonblocking_states free_state;

    /* State variables used in libssh2_session_disconnect_ex() */
    libssh2_nonblocking_states disconnect_state;
    unsigned char *disconnect_data;
    unsigned long disconnect_data_len;

    /* State variables used in libssh2_packet_read() */
    libssh2_nonblocking_states readPack_state;
    int readPack_encrypted;

    /* State variables used in libssh2_userauth_list() */
    libssh2_nonblocking_states userauth_list_state;
    unsigned char *userauth_list_data;
    unsigned long userauth_list_data_len;
    packet_requirev_state_t userauth_list_packet_requirev_state;

    /* State variables used in libssh2_userauth_password_ex() */
    libssh2_nonblocking_states userauth_pswd_state;
    unsigned char *userauth_pswd_data;
    unsigned char userauth_pswd_data0;
    unsigned long userauth_pswd_data_len;
    char *userauth_pswd_newpw;
    int userauth_pswd_newpw_len;
    packet_requirev_state_t userauth_pswd_packet_requirev_state;

    /* State variables used in libssh2_userauth_hostbased_fromfile_ex() */
    libssh2_nonblocking_states userauth_host_state;
    unsigned char *userauth_host_data;
    unsigned long userauth_host_data_len;
    unsigned char *userauth_host_packet;
    unsigned long userauth_host_packet_len;
    unsigned char *userauth_host_method;
    unsigned long userauth_host_method_len;
    unsigned char *userauth_host_s;
    packet_requirev_state_t userauth_host_packet_requirev_state;

    /* State variables used in libssh2_userauth_publickey_fromfile_ex() */
    libssh2_nonblocking_states userauth_pblc_state;
    unsigned char *userauth_pblc_data;
    unsigned long userauth_pblc_data_len;
    unsigned char *userauth_pblc_packet;
    unsigned long userauth_pblc_packet_len;
    unsigned char *userauth_pblc_method;
    unsigned long userauth_pblc_method_len;
    unsigned char *userauth_pblc_s;
    unsigned char *userauth_pblc_b;
    packet_requirev_state_t userauth_pblc_packet_requirev_state;

    /* State variables used in llibssh2_userauth_keyboard_interactive_ex() */
    libssh2_nonblocking_states userauth_kybd_state;
    unsigned char *userauth_kybd_data;
    unsigned long userauth_kybd_data_len;
    unsigned char *userauth_kybd_packet;
    unsigned long userauth_kybd_packet_len;
    unsigned int userauth_kybd_auth_name_len;
    char *userauth_kybd_auth_name;
    unsigned userauth_kybd_auth_instruction_len;
    char *userauth_kybd_auth_instruction;
    unsigned int userauth_kybd_num_prompts;
    int userauth_kybd_auth_failure;
    LIBSSH2_USERAUTH_KBDINT_PROMPT *userauth_kybd_prompts;
    LIBSSH2_USERAUTH_KBDINT_RESPONSE *userauth_kybd_responses;
    packet_requirev_state_t userauth_kybd_packet_requirev_state;

    /* State variables used in libssh2_channel_open_ex() */
    libssh2_nonblocking_states open_state;
    packet_requirev_state_t open_packet_requirev_state;
    LIBSSH2_CHANNEL *open_channel;
    unsigned char *open_packet;
    unsigned long open_packet_len;
    unsigned char *open_data;
    unsigned long open_data_len;
    unsigned long open_local_channel;

    /* State variables used in libssh2_channel_direct_tcpip_ex() */
    libssh2_nonblocking_states direct_state;
    unsigned char *direct_message;
    unsigned long direct_host_len;
    unsigned long direct_shost_len;
    unsigned long direct_message_len;

    /* State variables used in libssh2_channel_forward_listen_ex() */
    libssh2_nonblocking_states fwdLstn_state;
    unsigned char *fwdLstn_packet;
    unsigned long fwdLstn_host_len;
    unsigned long fwdLstn_packet_len;
    packet_requirev_state_t fwdLstn_packet_requirev_state;

    /* State variables used in libssh2_publickey_init() */
    libssh2_nonblocking_states pkeyInit_state;
    LIBSSH2_PUBLICKEY *pkeyInit_pkey;
    LIBSSH2_CHANNEL *pkeyInit_channel;
    unsigned char *pkeyInit_data;
    unsigned long pkeyInit_data_len;

    /* State variables used in libssh2_packet_add() */
    libssh2_nonblocking_states packAdd_state;
    LIBSSH2_PACKET *packAdd_packet;
    LIBSSH2_CHANNEL *packAdd_channel;
    unsigned long packAdd_data_head;
    key_exchange_state_t packAdd_key_state;
    packet_queue_listener_state_t packAdd_Qlstn_state;
    packet_x11_open_state_t packAdd_x11open_state;

    /* State variables used in fullpacket() */
    libssh2_nonblocking_states fullpacket_state;
    int fullpacket_macstate;
    int fullpacket_payload_len;
    libssh2pack_t fullpacket_packet_type;

    /* State variables used in libssh2_sftp_init() */
    libssh2_nonblocking_states sftpInit_state;
    LIBSSH2_SFTP *sftpInit_sftp;
    LIBSSH2_CHANNEL *sftpInit_channel;
    unsigned char sftpInit_buffer[9];   /* sftp_header(5){excludes request_id} + version_id(4) */

    /* State variables used in libssh2_scp_recv() */
    libssh2_nonblocking_states scpRecv_state;
    unsigned char *scpRecv_command;
    unsigned long scpRecv_command_len;
    unsigned char scpRecv_response[LIBSSH2_SCP_RESPONSE_BUFLEN];
    unsigned long scpRecv_response_len;
    long scpRecv_mode;
#if defined(HAVE_LONGLONG) && defined(strtoll)
    /* we have the type and we can parse such numbers */
    long long scpRecv_size;
#define scpsize_strtol strtoll
#else
    long scpRecv_size;
#define scpsize_strtol strtol
#endif
    long scpRecv_mtime;
    long scpRecv_atime;
    char *scpRecv_err_msg;
    long scpRecv_err_len;
    LIBSSH2_CHANNEL *scpRecv_channel;

    /* State variables used in libssh2_scp_send_ex() */
    libssh2_nonblocking_states scpSend_state;
    unsigned char *scpSend_command;
    unsigned long scpSend_command_len;
    unsigned char scpSend_response[LIBSSH2_SCP_RESPONSE_BUFLEN];
    unsigned long scpSend_response_len;
    char *scpSend_err_msg;
    long scpSend_err_len;
    LIBSSH2_CHANNEL *scpSend_channel;
};

/* session.state bits */
#define LIBSSH2_STATE_EXCHANGING_KEYS   0x00000001
#define LIBSSH2_STATE_NEWKEYS           0x00000002
#define LIBSSH2_STATE_AUTHENTICATED     0x00000004
#define LIBSSH2_STATE_KEX_ACTIVE        0x00000008

/* session.flag helpers */
#ifdef MSG_NOSIGNAL
#define LIBSSH2_SOCKET_SEND_FLAGS(session)      (((session)->flags & LIBSSH2_FLAG_SIGPIPE) ? 0 : MSG_NOSIGNAL)
#define LIBSSH2_SOCKET_RECV_FLAGS(session)      (((session)->flags & LIBSSH2_FLAG_SIGPIPE) ? 0 : MSG_NOSIGNAL)
#else
/* If MSG_NOSIGNAL isn't defined we're SOL on blocking SIGPIPE */
#define LIBSSH2_SOCKET_SEND_FLAGS(session)      0
#define LIBSSH2_SOCKET_RECV_FLAGS(session)      0
#endif

/* libssh2 extensible ssh api, ultimately I'd like to allow loading additional methods via .so/.dll */

struct _LIBSSH2_KEX_METHOD
{
    const char *name;

    /* Key exchange, populates session->* and returns 0 on success, non-0 on error */
    int (*exchange_keys) (LIBSSH2_SESSION * session,
                          key_exchange_state_low_t * key_state);

    long flags;
};

struct _LIBSSH2_HOSTKEY_METHOD
{
    const char *name;
    unsigned long hash_len;

    int (*init) (LIBSSH2_SESSION * session, const unsigned char *hostkey_data,
                 unsigned long hostkey_data_len, void **abstract);
    int (*initPEM) (LIBSSH2_SESSION * session, const char *privkeyfile,
                    unsigned const char *passphrase, void **abstract);
    int (*sig_verify) (LIBSSH2_SESSION * session, const unsigned char *sig,
                       unsigned long sig_len, const unsigned char *m,
                       unsigned long m_len, void **abstract);
    int (*signv) (LIBSSH2_SESSION * session, unsigned char **signature,
                  unsigned long *signature_len, unsigned long veccount,
                  const struct iovec datavec[], void **abstract);
    int (*encrypt) (LIBSSH2_SESSION * session, unsigned char **dst,
                    unsigned long *dst_len, const unsigned char *src,
                    unsigned long src_len, void **abstract);
    int (*dtor) (LIBSSH2_SESSION * session, void **abstract);
};

struct _LIBSSH2_CRYPT_METHOD
{
    const char *name;

    int blocksize;

    /* iv and key sizes (-1 for variable length) */
    int iv_len;
    int secret_len;

    long flags;

    int (*init) (LIBSSH2_SESSION * session,
                 const LIBSSH2_CRYPT_METHOD * method, unsigned char *iv,
                 int *free_iv, unsigned char *secret, int *free_secret,
                 int encrypt, void **abstract);
    int (*crypt) (LIBSSH2_SESSION * session, unsigned char *block,
                  void **abstract);
    int (*dtor) (LIBSSH2_SESSION * session, void **abstract);

      _libssh2_cipher_type(algo);
};

struct _LIBSSH2_COMP_METHOD
{
    const char *name;

    int (*init) (LIBSSH2_SESSION * session, int compress, void **abstract);
    int (*comp) (LIBSSH2_SESSION * session, int compress, unsigned char **dest,
                 unsigned long *dest_len, unsigned long payload_limit,
                 int *free_dest, const unsigned char *src,
                 unsigned long src_len, void **abstract);
    int (*dtor) (LIBSSH2_SESSION * session, int compress, void **abstract);
};

struct _LIBSSH2_MAC_METHOD
{
    const char *name;

    /* The length of a given MAC packet */
    int mac_len;

    /* integrity key length */
    int key_len;

    /* Message Authentication Code Hashing algo */
    int (*init) (LIBSSH2_SESSION * session, unsigned char *key, int *free_key,
                 void **abstract);
    int (*hash) (LIBSSH2_SESSION * session, unsigned char *buf,
                 unsigned long seqno, const unsigned char *packet,
                 unsigned long packet_len, const unsigned char *addtl,
                 unsigned long addtl_len, void **abstract);
    int (*dtor) (LIBSSH2_SESSION * session, void **abstract);
};

#define LIBSSH2_DBG_TRANS   1
#define LIBSSH2_DBG_KEX     2
#define LIBSSH2_DBG_AUTH    3
#define LIBSSH2_DBG_CONN    4
#define LIBSSH2_DBG_SCP     5
#define LIBSSH2_DBG_SFTP    6
#define LIBSSH2_DBG_ERROR   7
#define LIBSSH2_DBG_PUBLICKEY   8
#ifdef LIBSSH2DEBUG
void _libssh2_debug(LIBSSH2_SESSION * session, int context, const char *format,
                    ...);
#else
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
/* C99 style */
#define _libssh2_debug(x,y,z, __VA_ARGS__) do {} while (0)
#elif defined(__GNUC__)
/* GNU style */
#define _libssh2_debug(x,y,z,...) do {} while (0)
#else
/* no gcc and not C99, do static and hopefully inline */
static inline void
_libssh2_debug(LIBSSH2_SESSION * session, int context, const char *format, ...)
{
}
#endif
#endif

#ifdef LIBSSH2DEBUG
#define libssh2_error(session, errcode, errmsg, should_free)    \
{ \
    if (session->err_msg && session->err_should_free) { \
        LIBSSH2_FREE(session, session->err_msg); \
    } \
    session->err_msg = (char *)errmsg; \
    session->err_msglen = strlen(errmsg); \
    session->err_should_free = should_free; \
    session->err_code = errcode; \
    _libssh2_debug(session, LIBSSH2_DBG_ERROR, "%d - %s", session->err_code, session->err_msg); \
}

#else /* ! LIBSSH2DEBUG */

#define libssh2_error(session, errcode, errmsg, should_free)    \
{ \
    if (session->err_msg && session->err_should_free) { \
        LIBSSH2_FREE(session, session->err_msg); \
    } \
    session->err_msg = (char *)errmsg; \
    session->err_msglen = strlen(errmsg); \
    session->err_should_free = should_free; \
    session->err_code = errcode; \
}

#endif /* ! LIBSSH2DEBUG */


#define LIBSSH2_SOCKET_UNKNOWN                   1
#define LIBSSH2_SOCKET_CONNECTED                 0
#define LIBSSH2_SOCKET_DISCONNECTED             -1

/* Initial packet state, prior to MAC check */
#define LIBSSH2_MAC_UNCONFIRMED                  1
/* When MAC type is "none" (proto initiation phase) all packets are deemed "confirmed" */
#define LIBSSH2_MAC_CONFIRMED                    0
/* Something very bad is going on */
#define LIBSSH2_MAC_INVALID                     -1

/* SSH Packet Types -- Defined by internet draft */
/* Transport Layer */
#define SSH_MSG_DISCONNECT                          1
#define SSH_MSG_IGNORE                              2
#define SSH_MSG_UNIMPLEMENTED                       3
#define SSH_MSG_DEBUG                               4
#define SSH_MSG_SERVICE_REQUEST                     5
#define SSH_MSG_SERVICE_ACCEPT                      6

#define SSH_MSG_KEXINIT                             20
#define SSH_MSG_NEWKEYS                             21

/* diffie-hellman-group1-sha1 */
#define SSH_MSG_KEXDH_INIT                          30
#define SSH_MSG_KEXDH_REPLY                         31

/* diffie-hellman-group-exchange-sha1 */
#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD              30
#define SSH_MSG_KEX_DH_GEX_REQUEST                  34
#define SSH_MSG_KEX_DH_GEX_GROUP                    31
#define SSH_MSG_KEX_DH_GEX_INIT                     32
#define SSH_MSG_KEX_DH_GEX_REPLY                    33

/* User Authentication */
#define SSH_MSG_USERAUTH_REQUEST                    50
#define SSH_MSG_USERAUTH_FAILURE                    51
#define SSH_MSG_USERAUTH_SUCCESS                    52
#define SSH_MSG_USERAUTH_BANNER                     53

/* "public key" method */
#define SSH_MSG_USERAUTH_PK_OK                      60
/* "password" method */
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ           60
/* "keyboard-interactive" method */
#define SSH_MSG_USERAUTH_INFO_REQUEST               60
#define SSH_MSG_USERAUTH_INFO_RESPONSE              61

/* Channels */
#define SSH_MSG_GLOBAL_REQUEST                      80
#define SSH_MSG_REQUEST_SUCCESS                     81
#define SSH_MSG_REQUEST_FAILURE                     82

#define SSH_MSG_CHANNEL_OPEN                        90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION           91
#define SSH_MSG_CHANNEL_OPEN_FAILURE                92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST               93
#define SSH_MSG_CHANNEL_DATA                        94
#define SSH_MSG_CHANNEL_EXTENDED_DATA               95
#define SSH_MSG_CHANNEL_EOF                         96
#define SSH_MSG_CHANNEL_CLOSE                       97
#define SSH_MSG_CHANNEL_REQUEST                     98
#define SSH_MSG_CHANNEL_SUCCESS                     99
#define SSH_MSG_CHANNEL_FAILURE                     100

void libssh2_session_shutdown(LIBSSH2_SESSION * session);

unsigned long libssh2_ntohu32(const unsigned char *buf);
libssh2_uint64_t libssh2_ntohu64(const unsigned char *buf);
void libssh2_htonu32(unsigned char *buf, unsigned long val);
void libssh2_htonu64(unsigned char *buf, libssh2_uint64_t val);

#define LIBSSH2_READ_TIMEOUT 60 /* generic timeout in seconds used when
                                   waiting for more data to arrive */
int libssh2_waitsocket(LIBSSH2_SESSION * session, long seconds);


/* CAUTION: some of these error codes are returned in the public API and is
   there known with other #defined names from the public header file. They
   should not be changed. */

#define PACKET_TIMEOUT  -7
#define PACKET_BADUSE   -6
#define PACKET_COMPRESS -5
#define PACKET_TOOBIG   -4
#define PACKET_ENOMEM   -3
#define PACKET_EAGAIN   LIBSSH2_ERROR_EAGAIN
#define PACKET_FAIL     -1
#define PACKET_NONE      0

libssh2pack_t libssh2_packet_read(LIBSSH2_SESSION * session);

int libssh2_packet_ask_ex(LIBSSH2_SESSION * session, unsigned char packet_type,
                          unsigned char **data, unsigned long *data_len,
                          unsigned long match_ofs,
                          const unsigned char *match_buf,
                          unsigned long match_len, int poll_socket);

int libssh2_packet_askv_ex(LIBSSH2_SESSION * session,
                           const unsigned char *packet_types,
                           unsigned char **data, unsigned long *data_len,
                           unsigned long match_ofs,
                           const unsigned char *match_buf,
                           unsigned long match_len, int poll_socket);
int libssh2_packet_require_ex(LIBSSH2_SESSION * session,
                              unsigned char packet_type, unsigned char **data,
                              unsigned long *data_len, unsigned long match_ofs,
                              const unsigned char *match_buf,
                              unsigned long match_len,
                              packet_require_state_t * state);
int libssh2_packet_requirev_ex(LIBSSH2_SESSION * session,
                               const unsigned char *packet_types,
                               unsigned char **data, unsigned long *data_len,
                               unsigned long match_ofs,
                               const unsigned char *match_buf,
                               unsigned long match_len,
                               packet_requirev_state_t * state);
int libssh2_packet_burn(LIBSSH2_SESSION * session,
                        libssh2_nonblocking_states * state);
int libssh2_packet_write(LIBSSH2_SESSION * session, unsigned char *data,
                         unsigned long data_len);
int libssh2_packet_add(LIBSSH2_SESSION * session, unsigned char *data,
                       size_t datalen, int macstate);
int libssh2_kex_exchange(LIBSSH2_SESSION * session, int reexchange,
                         key_exchange_state_t * state);
unsigned long libssh2_channel_nextid(LIBSSH2_SESSION * session);
LIBSSH2_CHANNEL *libssh2_channel_locate(LIBSSH2_SESSION * session,
                                        unsigned long channel_id);
unsigned long libssh2_channel_packet_data_len(LIBSSH2_CHANNEL * channel,
                                              int stream_id);

/* this is the lib-internal set blocking function */
int _libssh2_session_set_blocking(LIBSSH2_SESSION * session, int blocking);

/* Let crypt.c/hostkey.c/comp.c/mac.c expose their method structs */
const LIBSSH2_CRYPT_METHOD **libssh2_crypt_methods(void);
const LIBSSH2_HOSTKEY_METHOD **libssh2_hostkey_methods(void);
const LIBSSH2_COMP_METHOD **libssh2_comp_methods(void);
const LIBSSH2_MAC_METHOD **libssh2_mac_methods(void);

/* Language API doesn't exist yet.  Just act like we've agreed on a language */
#define libssh2_kex_agree_lang(session, endpoint, str, str_len) 0

/* pem.c */
int _libssh2_pem_parse(LIBSSH2_SESSION * session,
                       const char *headerbegin,
                       const char *headerend,
                       FILE * fp, unsigned char **data, unsigned int *datalen);
int _libssh2_pem_decode_sequence(unsigned char **data, unsigned int *datalen);
int _libssh2_pem_decode_integer(unsigned char **data, unsigned int *datalen,
                                unsigned char **i, unsigned int *ilen);

#endif /* LIBSSH2_H */
