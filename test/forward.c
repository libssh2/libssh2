/*
 * forward.c -- ssh2 port forwarding test
 *
 * Copyright (C) 2005 Bert Vermeulen <bert@biot.com>
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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <wordexp.h>

#include <libssh2.h>
#include "libssh2-test.h"

struct authdefs auth;
extern struct addrinfo *cur_ai;

#define LISTEN_PORT   22617
#define TESTBUF_SIZE  10


static int loopback(LIBSSH2_SESSION *session, int hostbind, int portbind)
{
     LIBSSH2_CHANNEL *inbound, *outbound;
     LIBSSH2_LISTENER *listener;
     int listen_port, size, i, res;
     char paramstr[64], ipstr[128], *errmsg, *host, *sendbuf, *recvbuf;

     snprintf(paramstr, 64, "(%shost bind, %sport bind)", hostbind ? "" : "no ", portbind ? "" : "no ");

     host = NULL;
     if(hostbind)
     {
	  if(getnameinfo(cur_ai->ai_addr, cur_ai->ai_addrlen, ipstr, sizeof(ipstr), NULL, 0, NI_NUMERICHOST))
	  {
	       log_line(ERROR, "getnameinfo() failed\n");
	       return(0);
	  }
	  host = ipstr;
     }

     listen_port = 0;
     if(portbind)
	  listen_port = LISTEN_PORT;

     listener = libssh2_channel_forward_listen_ex(session, host, listen_port, &listen_port, 2);
     if(!listener)
     {
	  libssh2_session_last_error(session, &errmsg, &size, 0);
	  log_line(ERROR, "Listen failed %s: %s\n", paramstr, errmsg);

	  return(0);
     }

     outbound = libssh2_channel_direct_tcpip(session, auth.hostname, listen_port);
     if(!outbound)
     {
	  libssh2_session_last_error(session, &errmsg, &size, 0);
	  log_line(ERROR, "Outbound channel setup failed %s: %s\n", paramstr, errmsg);

	  libssh2_channel_forward_cancel(listener);

	  return(0);
     }

     inbound = libssh2_channel_forward_accept(listener);
     if(!inbound)
     {
	  libssh2_session_last_error(session, &errmsg, &size, 0);
	  log_line(ERROR, "Forwarding channel accept failed %s: %s\n", paramstr, errmsg);

	  libssh2_channel_free(outbound);
	  libssh2_channel_forward_cancel(listener);

	  return(0);
     }

     sendbuf = malloc(TESTBUF_SIZE);
     if(!sendbuf)
     {
	  log_line(ERROR, "sendbuf malloc failed\n");

	  libssh2_channel_free(inbound);
	  libssh2_channel_free(outbound);
	  libssh2_channel_forward_cancel(listener);

	  return(0);
     }

     for(i = 0; i < TESTBUF_SIZE; i++)
	  sendbuf[i] = (char) random;

     res = libssh2_channel_write(outbound, sendbuf, TESTBUF_SIZE);
     if(res != TESTBUF_SIZE)
     {
	  if(res == -1)
	       libssh2_session_last_error(session, &errmsg, &size, 0);
	  else
	       errmsg = NULL;
	  log_line(ERROR, "Unable to send %d bytes across tunnel %s%s%s\n",
		   TESTBUF_SIZE, paramstr, errmsg ? ": " : "", errmsg ? errmsg : "");

	  free(sendbuf);
	  libssh2_channel_free(inbound);
	  libssh2_channel_free(outbound);
	  libssh2_channel_forward_cancel(listener);

	  return(0);
     }

     recvbuf = malloc(TESTBUF_SIZE);
     if(!recvbuf)
     {
	  log_line(ERROR, "recvbuf malloc failed\n");

	  free(sendbuf);
	  libssh2_channel_free(inbound);
	  libssh2_channel_free(outbound);
	  libssh2_channel_forward_cancel(listener);

	  return(0);
     }

     res = libssh2_channel_read(inbound, recvbuf, TESTBUF_SIZE);
     if(res != TESTBUF_SIZE)
     {
	  if(res == -1)
	       libssh2_session_last_error(session, &errmsg, &size, 0);
	  else
	       errmsg = NULL;
	  log_line(ERROR, "Unable to receive %d bytes across tunnel %s%s%s\n",
		   TESTBUF_SIZE, paramstr, errmsg ? ": " : "", errmsg ? errmsg : "");

	  free(sendbuf);
	  free(recvbuf);
	  libssh2_channel_free(inbound);
	  libssh2_channel_free(outbound);
	  libssh2_channel_forward_cancel(listener);

	  return(0);
     }

     res = 1;
     for(i = 0; i < TESTBUF_SIZE; i++)
     {
	  if(recvbuf[i] != sendbuf[i])
	  {
	       log_line(ERROR, "Received data did not match sent data %s\n", paramstr);

	       res = 0;
	       break;
	  }
     }

     free(sendbuf);
     free(recvbuf);
     libssh2_channel_free(inbound);
     libssh2_channel_free(outbound);
     libssh2_channel_forward_cancel(listener);

     return(res);
}


static void all_forward(void)
{
     LIBSSH2_SESSION *session;
     int sock, res, size;
     char *errmsg;

     sock = new_socket();
     if(sock == -1)
     {
	  log_line(ERROR, "Unable to open a socket\n");
	  return;
     }

     session = libssh2_session_init();

     res = libssh2_session_startup(session, sock);
     if(res)
     {
	  libssh2_session_last_error(session, &errmsg, &size, 0);
	  log_line(ERROR, "Session startup failed: %s\n", errmsg);
	  close(sock);
	  return;
     }

     if(libssh2_userauth_password(session, auth.username, auth.password))
     {
	  libssh2_session_last_error(session, &errmsg, &size, 0);
	  log_line(ERROR, "Authentication failed%s%s\n", errmsg[0] ? ": " : "", errmsg);
	  libssh2_session_disconnect(session, "All done.");
	  libssh2_session_free(session);
	  close(sock);
	  return;
     }

     increase_progress();
     if(loopback(session, 1, 1))
	  step_successful();

     increase_progress();
     if(loopback(session, 1, 0))
	  step_successful();

     increase_progress();
     if(loopback(session, 0, 1))
	  step_successful();

     increase_progress();
     if(loopback(session, 0, 0))
	  step_successful();

     libssh2_session_disconnect(session, "All done.");
     libssh2_session_free(session);
     close(sock);
     printf("\n");

}





void runtest_forward(void)
{

     init_test("TCP port forwarding/tunneling", 4);

     all_forward();

}
