/*
 * auth.c -- test authentication methods
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <libssh2.h>
#include "libssh2-test.h"

extern struct authdefs auth;


static int auth_publickey(LIBSSH2_SESSION *session)
{

     if(libssh2_userauth_publickey_fromfile(session, auth.username,
					    auth.pubkey, auth.privkey, auth.passphrase))
     {
	  log_line(ERROR, "Public key authentication failed\n");
	  return(0);
     }

     if(!libssh2_userauth_authenticated(session))
     {
	  log_line(ERROR, "Public key authentication succeeded, but authentication not set\n");
	  return(0);
     }

     return(1);
}


static int auth_password(LIBSSH2_SESSION *session)
{

     if(libssh2_userauth_password(session, auth.username, auth.password))
     {
	  log_line(ERROR, "Password authentication failed\n");
	  return(0);
     }

     if(!libssh2_userauth_authenticated(session))
     {
	  log_line(ERROR, "Password authentication succeeded, but authentication not set\n");
	  return(0);
     }

     return(1);
}


static void all_auth(void)
{
     LIBSSH2_SESSION *session;
     int sock, size, res, sum, i;
     unsigned char *hash;
     char *errmsg, *_authlist, *authlist, *authmethod, *sep;

     authlist = NULL;
     authmethod = "";
     while(authmethod)
     {
	  sock = new_socket();
	  if(sock == -1)
	  {
	       log_line(ERROR, "new_socket() failed\n");
	       return;
	  }

	  session = libssh2_session_init();

	  res = libssh2_session_startup(session, sock);
	  if(res)
	  {
	       libssh2_session_last_error(session, &errmsg, &size, 0);
	       log_line(ERROR, "session_startup() failed: %s\n", errmsg);
	       close(sock);
	       return;
	  }

	  if(!authlist)
	  {
	       _authlist = libssh2_userauth_list(session, auth.username, strlen(auth.username));
	       if(_authlist == NULL)
	       {
		    libssh2_session_last_error(session, &errmsg, &size, 0);
		    log_line(ERROR, "userauth_list() failed: %s\n", errmsg);
		    libssh2_session_disconnect(session, "All done.");
		    libssh2_session_free(session);
		    close(sock);
		    return;
	       }

	       authlist = strdup(_authlist);
	       authmethod = authlist;

	       /* only need to check hostkey hashes once... might as well do that here */
	       increase_progress();
	       hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_MD5);
	       if(hash)
	       {
		    sum = 0;
		    for(i = 0; i < 16; i++)
			 sum += hash[i];
		    if(sum > 0)
			 step_successful();
		    else
			 log_line(ERROR, "MD5 hostkey hash invalid\n");
	       }
	       else
		    log_line(ERROR, "MD5 hostkey hash failed\n");

	       increase_progress();
	       hash = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
	       if(hash)
	       {
		    sum = 0;
		    for(i = 0; i < 20; i++)
			 sum += hash[i];
		    if(sum > 0)
			 step_successful();
		    else
			 log_line(ERROR, "SHA1 hostkey hash invalid\n");
	       }
	       else
		    log_line(ERROR, "SHA1 hostkey hash failed\n");

	  }

	  if( (sep = strchr(authmethod, ',')) )
	       *sep++ = '\0';

	  if(!strcasecmp(authmethod, "publickey"))
	  {
	       increase_progress();
	       if(auth_publickey(session))
		    step_successful();
	  }
	  else if(!strcasecmp(authmethod, "password"))
	  {
	       increase_progress();
	       if(auth_password(session))
		    step_successful();
	  }
	  else if(!strcasecmp(authmethod, "keyboard-interactive"))
	  {
	       /* no idea how to test this */
	  }
	  else
	  {
	       log_line(DEBUG, "Unknown authentication method %s\n", authmethod);
	  }

	  authmethod = sep;

	  libssh2_session_disconnect(session, "All done.");
	  libssh2_session_free(session);
	  close(sock);
     }

     free(authlist);

     printf("\n");

}


void runtest_auth(void)
{

     init_test("authentication", 4);

     all_auth();

}

