/*
 * methods.c -- test all available key exchange, hostkey, encryption, mac
 * and compression methods
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

#include <libssh2.h>
#include "libssh2-test.h"

extern struct authdefs auth;


static char *kex_methods[] = {
     "diffie-hellman-group1-sha1",
     "diffie-hellman-group14-sha1",
     "diffie-hellman-group-exchange-sha1",
     NULL
};

static char *hostkey_methods[] = {
     "ssh-dss",
     "ssh-rsa",
     NULL
};

static char *crypt_methods[] = {
     "3des-cbc",
     "aes256-cbc",
     "aes192-cbc",
     "aes128-cbc",
     "blowfish-cbc",
     "arcfour",
     "cast128-cbc",
     NULL
};

static char *mac_methods[] = {
     "hmac-sha1",
     "hmac-sha1-96",
     "hmac-md5",
     "hmac-md5-96",
     "hmac-ripemd160",
     NULL
};

static char *compression_methods[] = {
     "none",
     "zlib",
     NULL
};


static struct methodlist methods[] = {
     { LIBSSH2_METHOD_KEX,      "kex",              kex_methods,         0, 0 },
     { LIBSSH2_METHOD_HOSTKEY,  "hostkey",          hostkey_methods,     0, 0 },
     { LIBSSH2_METHOD_CRYPT_CS, "crypt (cs)",       crypt_methods,       0, 0 },
     { LIBSSH2_METHOD_CRYPT_SC, "crypt (sc)",       crypt_methods,       0, 0 },
     { LIBSSH2_METHOD_MAC_CS,   "MAC (cs)",         mac_methods,         0, 0 },
     { LIBSSH2_METHOD_MAC_SC,   "MAC (sc)",         mac_methods,         0, 0 },
     { LIBSSH2_METHOD_COMP_CS,  "compression (cs)", compression_methods, 0, 0 },
     { LIBSSH2_METHOD_COMP_SC,  "compression (sc)", compression_methods, 0, 0 },
     { 0, NULL, NULL, 0, 0 }
};


/*
static void dump_methods(LIBSSH2_SESSION *session)
{

     printf("    Key exchange methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_KEX));
     printf("         Hostkey methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_HOSTKEY));
     printf("      Crypt C->S methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_CS));
     printf("      Crypt S->C methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC));
     printf("        MAC C->S methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_MAC_CS));
     printf("        MAC S->C methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_MAC_SC));
     printf("Compression C->S methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_COMP_CS));
     printf("Compression S->C methods: %s\n", libssh2_session_methods(session, LIBSSH2_METHOD_COMP_SC));

}
*/


static void cycle_methods(void)
{
     LIBSSH2_SESSION *session;
     int sock, size, res, method_type, method, i;
     char *errmsg;

     method_type = 0;
     method = 0;
     while(methods[method_type].description)
     {
	  while(methods[method_type].list[method])
	  {
	       increase_progress();
	       sock = new_socket();
	       if(sock == -1)
	       {
		    log_line(ERROR, "new_socket() failed");
		    return;
	       }

	       session = libssh2_session_init();



	       for(i = 0; methods[i].description; i++)
	       {
		    res = libssh2_session_method_pref(session, methods[i].method_type,
						      methods[i].list[ i == method_type ? method : 0 ]);
		    if(res != 0)
		    {
			 libssh2_session_last_error(session, &errmsg, &size, 0);
			 log_line(ERROR, "%s method set to '%s' failed: %s\n",
				  methods[i].description,
				  methods[i].list[ i == method_type ? method : 0 ], errmsg);
			 return;
		    }

		    i++;
	       }

	       res = libssh2_session_startup(session, sock);
	       if(res == 0)
	       {
		    if(libssh2_userauth_password(session, auth.username, auth.password))
		    {
			 log_line(ERROR, "Authentication failed\n");
		    }
		    else
			 step_successful();
	       }
	       else
	       {
		    libssh2_session_last_error(session, &errmsg, &size, 0);
		    log_line(ERROR, "session startup for %s method %s failed: %s\n",
			     methods[method_type].description, methods[method_type].list[method], errmsg);
	       }

	       libssh2_session_disconnect(session, "All done.");
	       libssh2_session_free(session);
	       close(sock);

	       method++;
	  }
	  method_type++;
	  method = 1;
     }
     printf("\n");

}


void runtest_methods(void)
{
     int i, j, num_steps;

     num_steps = 0;
     for(i = 0; methods[i].description; i++)
     {
	  for(j = 0; methods[i].list[j]; j++)
	       ;
	  num_steps += j - 1;
     }
     num_steps++;

     init_test("kex/hostkey/crypt/max/compression methods", num_steps);

     cycle_methods();

}

