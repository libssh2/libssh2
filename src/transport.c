/* Copyright (C) 2007 The Written Word, Inc.  All rights reserved.
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
#include <errno.h>
#include <fcntl.h>

#include <assert.h>

#define MAX_BLOCKSIZE 32 /* MUST fit biggest crypto block size we use/get */
#define MAX_MACSIZE 20   /* MUST fit biggest MAC length we support */

#ifdef LIBSSH2DEBUG
#define UNPRINTABLE_CHAR '.'
static void debugdump(LIBSSH2_SESSION *session,
              const char *desc, unsigned char *ptr,
              unsigned long size)
{
  size_t i;
  size_t c;
  FILE *stream = stdout;
  unsigned int width=0x10;

  if (!(session->showmask & (1<< LIBSSH2_DBG_TRANS))) {
      /* not asked for, bail out */
      return;
  }

  fprintf(stream, "=> %s (%d bytes)\n", desc, (int)size);

  for(i=0; i<size; i+= width) {

    fprintf(stream, "%04lx: ", i);

    /* hex not disabled, show it */
    for(c = 0; c < width; c++) {
        if (i+c < size)
            fprintf(stream, "%02x ", ptr[i+c]);
        else
            fputs("   ", stream);
    }

    for(c = 0; (c < width) && (i+c < size); c++) {
        fprintf(stream, "%c",
            (ptr[i+c]>=0x20) &&
            (ptr[i+c]<0x80)?ptr[i+c]:UNPRINTABLE_CHAR);
    }
    fputc('\n', stream); /* newline */
  }
  fflush(stream);
}
#else
#define debugdump(a,x,y,z)
#endif


/* decrypt() decrypts 'len' bytes from 'source' to 'dest'.
 *
 * returns PACKET_NONE on success and PACKET_FAIL on failure
 */

static libssh2pack_t decrypt(LIBSSH2_SESSION *session, unsigned char *source,
                             unsigned char *dest, int len)
{
    struct transportpacket *p = &session->packet;
    int blocksize = session->remote.crypt->blocksize;
    
    /* if we get called with a len that isn't an even number of blocksizes
        we risk losing those extra bytes */
    assert((len % blocksize) == 0);
    
    while(len >= blocksize) {
        if (session->remote.crypt->crypt(session, source,
                                         &session->remote.crypt_abstract)) {
            libssh2_error(session, LIBSSH2_ERROR_DECRYPT,
                          (char *)"Error decrypting packet", 0);
            LIBSSH2_FREE(session, p->payload);
            return PACKET_FAIL;
        }
        
        /* if the crypt() function would write to a given address it
           wouldn't have to memcpy() and we could avoid this memcpy()
           too */
        memcpy(dest, source, blocksize);
        
        len -= blocksize;   /* less bytes left */
        dest += blocksize;   /* advance write pointer */
        source += blocksize; /* advance read pointer */
    }
    return PACKET_NONE; /* all is fine */
}

/*
 * fullpacket() gets called when a full packet has been received and properly
 * collected.
 */
static libssh2pack_t
fullpacket(LIBSSH2_SESSION *session, int encrypted /* 1 or 0 */)
{
    unsigned char macbuf[MAX_MACSIZE];
    struct transportpacket *p = &session->packet;
    int rc;
    
    if (session->fullpacket_state == libssh2_NB_state_idle) {
        session->fullpacket_macstate = LIBSSH2_MAC_CONFIRMED;
        session->fullpacket_payload_len = p->packet_length-1;
        
        if (encrypted) {
            
            /* Calculate MAC hash */
            session->remote.mac->hash(session,
                                      macbuf, /* store hash here */
                                      session->remote.seqno,
                                      p->init, 5,
                                      p->payload, session->fullpacket_payload_len,
                                      &session->remote.mac_abstract);
            
            /* Compare the calculated hash with the MAC we just read from
             * the network. The read one is at the very end of the payload
             * buffer. Note that 'payload_len' here is the packet_length
             * field which includes the padding but not the MAC.
             */
            if (memcmp(macbuf, p->payload + session->fullpacket_payload_len,
                       session->remote.mac->mac_len)) {
                session->fullpacket_macstate = LIBSSH2_MAC_INVALID;
            }
        }
        
        session->remote.seqno++;
        
        /* ignore the padding */
        session->fullpacket_payload_len -= p->padding_length;
        
        /* Check for and deal with decompression */
        if (session->remote.comp &&
            strcmp(session->remote.comp->name, "none")) {
            unsigned char *data;
            unsigned long data_len;
            int free_payload = 1;
            
            if (session->remote.comp->comp(session, 0,
                                           &data, &data_len,
                                           LIBSSH2_PACKET_MAXDECOMP,
                                           &free_payload,
                                           p->payload, session->fullpacket_payload_len,
                                           &session->remote.comp_abstract)) {
                LIBSSH2_FREE(session, p->payload);
                return PACKET_FAIL;
            }
            
            if (free_payload) {
                LIBSSH2_FREE(session, p->payload);
                p->payload = data;
                session->fullpacket_payload_len = data_len;
            }
            else {
                if (data == p->payload) {
                    /* It's not to be freed, because the
                     * compression layer reused payload, So let's
                     * do the same!
                     */
                    session->fullpacket_payload_len = data_len;
                }
                else {
                    /* No comp_method actually lets this happen,
                     * but let's prepare for the future */
                    
                    LIBSSH2_FREE(session, p->payload);
                    
                    /* We need a freeable struct otherwise the
                     * brigade won't know what to do with it */
                    p->payload = LIBSSH2_ALLOC(session, data_len);
                    if (!p->payload) {
                        libssh2_error(session,
                                      LIBSSH2_ERROR_ALLOC,
                                      (char *)"Unable to allocate memory for copy of uncompressed data", 0);
                        return PACKET_ENOMEM;
                    }
                    memcpy(p->payload, data, data_len);
                    session->fullpacket_payload_len = data_len;
                }
            }
        }
        
        session->fullpacket_packet_type = p->payload[0];
        
        debugdump(session, "libssh2_packet_read() plain",
                  p->payload, session->fullpacket_payload_len);
        
        session->fullpacket_state = libssh2_NB_state_created;
    }
    
    if (session->fullpacket_state == libssh2_NB_state_created) {
        rc = libssh2_packet_add(session, p->payload, session->fullpacket_payload_len, session->fullpacket_macstate);
        if (rc == PACKET_EAGAIN) {
            return PACKET_EAGAIN;
        }
        else if (rc < 0) {
            return PACKET_FAIL;
        }
    }
    
    session->fullpacket_state = libssh2_NB_state_idle;
    
    return session->fullpacket_packet_type;
}


/* {{{ libssh2_packet_read
 * Collect a packet into the input brigade
 * block only controls whether or not to wait for a packet to start,
 * Once a packet starts, libssh2 will block until it is complete
 *
 * Returns packet type added to input brigade (PACKET_NONE if nothing added),
 * or PACKET_FAIL on failure and PACKET_EAGAIN if it couldn't process a full
 * packet.
 */

/*
 * This function reads the binary stream as specified in chapter 6 of RFC4253
 * "The Secure Shell (SSH) Transport Layer Protocol"
 */
libssh2pack_t libssh2_packet_read(LIBSSH2_SESSION *session)
{
    libssh2pack_t rc;
    struct transportpacket *p = &session->packet;
    int remainbuf;
    int remainpack;
    int numbytes;
    int numdecrypt;
    unsigned char block[MAX_BLOCKSIZE];
    int blocksize;
    int minimum;
    int encrypted = 1;
    
    /*
     * =============================== NOTE ===============================
     * I know this is very ugly and not a really good use of "goto", but
     * this case statement would be even uglier to do it any other way
     */
    if (session->readPack_state == libssh2_NB_state_jump1) {
        session->readPack_state = libssh2_NB_state_idle;
        encrypted = session->readPack_encrypted;
        goto libssh2_packet_read_point1;
    }
        
    do {
        if (session->socket_state == LIBSSH2_SOCKET_DISCONNECTED) {
            return PACKET_NONE;
        }
        
        if (session->state & LIBSSH2_STATE_NEWKEYS) {
            blocksize = session->remote.crypt->blocksize;
        } else {
            encrypted = 0; /* not encrypted */
            blocksize = 5; /* not strictly true, but we can use 5 here to 
                              make the checks below work fine still */
        }
        minimum = p->total_num ? p->total_num - p->data_num : blocksize;
        
        /* read/use a whole big chunk into a temporary area stored in
           the LIBSSH2_SESSION struct. We will decrypt data from that
           buffer into the packet buffer so this temp one doesn't have
           to be able to keep a whole SSH packet, just be large enough
           so that we can read big chunks from the network layer. */
        
        /* how much data there is remaining in the buffer to deal with
           before we should read more from the network */
        remainbuf = p->writeidx - p->readidx;
        
        /* if remainbuf turns negative we have a bad internal error */
        assert(remainbuf >= 0);
        
        if (remainbuf < minimum) {
            /* If we have less than a minimum left, it is too
               little data to deal with, read more */
            ssize_t nread;
            
            /* move any remainder to the start of the buffer so
               that we can do a full refill */
            if (remainbuf) {
                memmove(p->buf, &p->buf[p->readidx], remainbuf);
                p->readidx = 0;
                p->writeidx = remainbuf;
            } else {
                /* nothing to move, just zero the indexes */
                p->readidx = p->writeidx = 0;
            }
            
            /* now read a big chunk from the network into the temp buffer */
            nread = recv(session->socket_fd, &p->buf[remainbuf], PACKETBUFSIZE-remainbuf,
                         LIBSSH2_SOCKET_RECV_FLAGS(session));
            if (nread <= 0) {
                /* check if this is due to EAGAIN and return
                   the special return code if so, error out
                   normally otherwise */
                if ((nread < 0) && (errno == EAGAIN)) {
                    return PACKET_EAGAIN;
                }
                return PACKET_FAIL;
            }
            debugdump(session, "libssh2_packet_read() raw",
                      &p->buf[remainbuf], nread);
            /* advance write pointer */
            p->writeidx += nread;
            
            /* update remainbuf counter */
            remainbuf = p->writeidx - p->readidx;
        }
        
        /* how much data to deal with from the buffer */
        numbytes = remainbuf;
        
        if (numbytes < blocksize) {
            /* we can't act on anything less than blocksize */
            return PACKET_EAGAIN;
        }
        
        if (!p->total_num) {
            /* No payload package area allocated yet. To know the
               size of this payload, we need to decrypt the first
               blocksize data. */
            
            if (encrypted) {
                rc = decrypt(session, &p->buf[p->readidx], block, blocksize);
                if (rc != PACKET_NONE) {
                    return rc;
                }
                /* save the first 5 bytes of the decrypted package, to be 
                   used in the hash calculation later down. */
                memcpy(p->init, &p->buf[p->readidx], 5);
            } else {
                /* the data is plain, just copy it verbatim to
                   the working block buffer */
                memcpy(block, &p->buf[p->readidx], blocksize);
            }
            
            /* advance the read pointer */
            p->readidx += blocksize;
            
            /* we now have the initial blocksize bytes decrypted,
             * and we can extract packet and padding length from it
             */
            p->packet_length = libssh2_ntohu32(block);
            p->padding_length = block[4];
            
            /* total_num is the number of bytes following the initial 
               (5 bytes) packet length and padding length fields */
            p->total_num = p->packet_length -1 + (encrypted ? session->remote.mac->mac_len : 0);
            
            /* RFC4253 section 6.1 Maximum Packet Length says:
             *
             * "All implementations MUST be able to process
             * packets with uncompressed payload length of 32768
             * bytes or less and total packet size of 35000 bytes
             * or less (including length, padding length, payload,
             * padding, and MAC.)."
             */
            if (p->total_num > LIBSSH2_PACKET_MAXPAYLOAD) {
                return PACKET_TOOBIG;
            }
            
            /* Get a packet handle put data into. We get one to
               hold all data, including padding and MAC. */
            p->payload = LIBSSH2_ALLOC(session, p->total_num);
            if (!p->payload) {
                return PACKET_ENOMEM;
            }
            /* init write pointer to start of payload buffer */
            p->wptr = p->payload;
            
            if (blocksize > 5) {
                /* copy the data from index 5 to the end of
                   the blocksize from the temporary buffer to
                   the start of the decrypted buffer */
                memcpy(p->wptr, &block[5], blocksize-5);
                p->wptr += blocksize-5; /* advance write pointer */
            }
            
            /* init the data_num field to the number of bytes of
               the package read so far */
            p->data_num = p->wptr - p->payload;
            
            /* we already dealt with a blocksize worth of data */
            numbytes -= blocksize;
        }
        
        /* how much there is left to add to the current payload
           package */
        remainpack = p->total_num - p->data_num;
        
        if (numbytes > remainpack) {
            /* if we have more data in the buffer than what is going into this 
               particular packet, we limit this round to this packet only */
            numbytes = remainpack;
        }
        
        if (encrypted) {
            /* At the end of the incoming stream, there is a MAC,
               and we don't want to decrypt that since we need it
               "raw". We MUST however decrypt the padding data
               since it is used for the hash later on. */
            int skip = session->remote.mac->mac_len;
            
            /* if what we have plus numbytes is bigger than the
               total minus the skip margin, we should lower the
               amount to decrypt even more */
            if ((p->data_num + numbytes) > (p->total_num - skip)) {
                numdecrypt = (p->total_num - skip) - p->data_num;
            } else {
                int frac;
                numdecrypt = numbytes;
                frac = numdecrypt % blocksize;
                if (frac) {
                    /* not an aligned amount of blocks,
                    align it */
                    numdecrypt -= frac;
                    /* and make it no unencrypted data
                    after it */
                    numbytes = 0;
                }
            }
        } else {
            /* unencrypted data should not be decrypted at all */
            numdecrypt = 0;
        }
        
        /* if there are bytes to decrypt, do that */
        if (numdecrypt > 0) {
            /* now decrypt the lot */
            rc = decrypt(session, &p->buf[p->readidx], p->wptr, numdecrypt);
            if (rc != PACKET_NONE) {
                return rc;
            }
            
            /* advance the read pointer */
            p->readidx += numdecrypt;
            /* advance write pointer */
            p->wptr += numdecrypt;
            /* increse data_num */
            p->data_num += numdecrypt;
            
            /* bytes left to take care of without decryption */
            numbytes -= numdecrypt;
        }
        
        /* if there are bytes to copy that aren't decrypted, simply
           copy them as-is to the target buffer */
        if (numbytes > 0) {
            memcpy(p->wptr, &p->buf[p->readidx], numbytes);
            
            /* advance the read pointer */
            p->readidx += numbytes;
            /* advance write pointer */
            p->wptr += numbytes;
            /* increse data_num */
            p->data_num += numbytes;
        }
        
        /* now check how much data there's left to read to finish the
           current packet */
        remainpack = p->total_num - p->data_num;
        
        if (!remainpack) {
            /* we have a full packet */
libssh2_packet_read_point1:
            rc = fullpacket(session, encrypted);
            if (rc == PACKET_EAGAIN) {
                session->readPack_encrypted = encrypted;
                session->readPack_state = libssh2_NB_state_jump1;
                return PACKET_EAGAIN;
            }
            
            p->total_num = 0; /* no packet buffer available */
            
            return rc;
        }
    } while (1); /* loop */

    return PACKET_FAIL; /* we never reach this point */
}
/* }}} */

#ifndef OLDSEND

static libssh2pack_t send_existing(LIBSSH2_SESSION *session, unsigned char *data, unsigned long data_len, ssize_t *ret)
{
    ssize_t rc;
    ssize_t length;
    struct transportpacket *p = &session->packet;
    
    if (!p->outbuf) {
        *ret = 0;
        return PACKET_NONE;
    }
    
    /* send as much as possible of the existing packet */
    if ((data != p->odata) || (data_len != p->olen)) {
        /* When we are about to complete the sending of a packet, it is vital 
           that the caller doesn't try to send a new/different packet since
           we don't add this one up until the previous one has been sent. To 
           make the caller really notice his/hers flaw, we return error for 
           this case */
        return PACKET_BADUSE;
    }
    
    *ret = 1; /* set to make our parent return */
    
    /* number of bytes left to send */
    length = p->ototal_num - p->osent;
    
    rc = send(session->socket_fd, &p->outbuf[p->osent], length, LIBSSH2_SOCKET_SEND_FLAGS(session));
    
    if (rc == length) {
        /* the remainder of the package was sent */
        LIBSSH2_FREE(session, p->outbuf);
        p->outbuf = NULL;
        p->ototal_num = 0;
    }
    else if (rc < 0) {
        /* nothing was sent */
        if (errno != EAGAIN) {
            /* send failure! */
            return PACKET_FAIL;
        }
        return PACKET_EAGAIN;
    }
    
    debugdump(session, "libssh2_packet_write send()", &p->outbuf[p->osent], length);
    p->osent += length; /* we sent away this much data */
    
    return PACKET_NONE;
}

/* {{{ libssh2_packet_write
 * Send a packet, encrypting it and adding a MAC code if necessary
 * Returns 0 on success, non-zero on failure.
 *
 * Returns PACKET_EAGAIN if it would block - and if it does so, you should
 * call this function again as soon as it is likely that more data can be
 * sent, and this function should then be called with the same argument set
 * (same data pointer and same data_len) until zero or failure is returned.
 */
int libssh2_packet_write(LIBSSH2_SESSION *session, unsigned char *data, unsigned long data_len)
{
    int blocksize = (session->state & LIBSSH2_STATE_NEWKEYS) ? session->local.crypt->blocksize : 8;
    int padding_length;
    int packet_length;
    int total_length;
    int free_data=0;
#ifdef RANDOM_PADDING
    int rand_max;
    int seed = data[0]; /* FIXME: make this random */
#endif
    struct transportpacket *p = &session->packet;
    int encrypted;
    int i;
    ssize_t ret;
    libssh2pack_t rc;
    unsigned char *orgdata = data;
    unsigned long orgdata_len = data_len;
    
    debugdump(session, "libssh2_packet_write plain", data, data_len);
    
    /* FIRST, check if we have a pending write to complete */
    rc = send_existing(session, data, data_len, &ret);
    if (rc || ret) {
        return rc;
    }
    
    encrypted = (session->state & LIBSSH2_STATE_NEWKEYS)?1:0;
    
    /* check if we should compress */
    if (encrypted && strcmp(session->local.comp->name, "none")) {
        if (session->local.comp->comp(session, 1, &data, &data_len, LIBSSH2_PACKET_MAXCOMP,
                                      &free_data, data, data_len, &session->local.comp_abstract)) {
            return PACKET_COMPRESS; /* compression failure */
        }
    }
    
    /* RFC4253 says: Note that the length of the concatenation of
       'packet_length', 'padding_length', 'payload', and 'random padding'
       MUST be a multiple of the cipher block size or 8, whichever is
       larger. */
    
    /* Plain math: (4 + 1 + packet_length + padding_length) % blocksize == 0 */
    
    packet_length = data_len + 1 + 4; /* 1 is for padding_length field
                                         4 for the packet_length field */
    
    /* at this point we have it all except the padding */
    
    /* first figure out our minimum padding amount to make it an even
       block size */
    padding_length = blocksize - (packet_length % blocksize);
    
    /* if the padding becomes too small we add another blocksize worth
       of it (taken from the original libssh2 where it didn't have any
       real explanation) */
    if (padding_length < 4) {
        padding_length += blocksize;
    }
#ifdef RANDOM_PADDING
    /* FIXME: we can add padding here, but that also makes the packets
       bigger etc */
    
    /* now we can add 'blocksize' to the padding_length N number of times
       (to "help thwart traffic analysis") but it must be less than 255 in
       total */
    rand_max = (255 - padding_length)/blocksize + 1;
    padding_length += blocksize * (seed % rand_max);
#endif
    
    packet_length += padding_length;
    
    /* append the MAC length to the total_length size */
    total_length = packet_length + (encrypted?session->local.mac->mac_len:0);
    
    /* allocate memory to store the outgoing packet in, in case we can't
       send the whole one and thus need to keep it after this function
       returns. */
    p->outbuf = LIBSSH2_ALLOC(session, total_length);
    if (!p->outbuf) {
        return PACKET_ENOMEM;
    }
    
    /* store packet_length, which is the size of the whole packet except
       the MAC and the packet_length field itself */
    libssh2_htonu32(p->outbuf, packet_length - 4);
    /* store padding_length */
    p->outbuf[4] = padding_length;
    /* copy the payload data */
    memcpy(p->outbuf + 5, data, data_len);
    /* fill the padding area with random junk */
    libssh2_random(p->outbuf + 5 + data_len, padding_length);
    if (free_data) {
        LIBSSH2_FREE(session, data);
    }
    
    if (encrypted) {
        /* Calculate MAC hash. Put the output at index packet_length,
           since that size includes the whole packet. The MAC is
           calculated on the entire unencrypted packet, including all
           fields except the MAC field itself. */
        session->local.mac->hash(session, p->outbuf + packet_length, session->local.seqno, p->outbuf, packet_length,
                                 NULL, 0, &session->local.mac_abstract);
        
        /* Encrypt the whole packet data, one block size at a time.
           The MAC field is not encrypted. */
        for(i=0; i < packet_length; i += session->local.crypt->blocksize) {
            unsigned char *ptr = &p->outbuf[i];
            if (session->local.crypt->crypt(session, ptr, &session->local.crypt_abstract))
                return PACKET_FAIL; /* encryption failure */
        }
    }
    
    session->local.seqno++;
    
    ret = send(session->socket_fd, p->outbuf, total_length, 
               LIBSSH2_SOCKET_SEND_FLAGS(session));
    
    if (ret != -1) {
        debugdump(session, "libssh2_packet_write send()", p->outbuf, ret);
    }
    if (ret != total_length) {
        if ((ret > 0 ) || ((ret == -1) && (errno == EAGAIN))) {
            /* the whole packet could not be sent, save the rest */
            p->odata = orgdata;
            p->olen = orgdata_len;
            p->osent = (ret == -1)?0:ret;
            p->ototal_num = total_length;
            return PACKET_EAGAIN;
        }
        return PACKET_FAIL;
    }
    
    /* the whole thing got sent away */
    p->odata = NULL;
    p->olen = 0;
    LIBSSH2_FREE(session, p->outbuf);
    p->outbuf = NULL;
    
    return PACKET_NONE; /* all is good */
}

/* }}} */
#endif
