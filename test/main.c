/*
 * main.c -- ssh2 protocol compliance tester for libssh2
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
char *progress_message;
int progress, progress_max;
struct addrinfo *hostai = NULL, *cur_ai = NULL;

extern struct logresults *testlogs;
extern struct logentry *logfile;



void cleanup(void)
{
     struct logresults *test, *nexttest;
     struct logentry *logfile, *nextlog;

     if(hostai)
	  freeaddrinfo(hostai);

     test = testlogs;
     while(test)
     {
	  logfile = test->log;
	  while(logfile)
	  {
	       nextlog = logfile->next;
	       free(logfile->logline);
	       free(logfile);

	       logfile = nextlog;
	  }
	  nexttest = test->next;
	  free(test);

	  test = nexttest;
     }

     free(auth.hostname);
     free(auth.port);
     free(auth.username);
     free(auth.password);
     free(auth.privkey);
     free(auth.pubkey);
     free(auth.passphrase);

}


char *get_interactive(char *prompt, int size, char *default_value)
{
     char *str;

     if( !(str = malloc(size)) )
     {
	  log_line(ERROR, "unable to malloc %d bytes for %s\n", size, prompt);
	  return(NULL);
     }

     printf("%s [%s]: ", prompt, default_value);
     fgets(str, size, stdin);
     if(str[strlen(str)-1] == '\n')
	  str[strlen(str)-1] = 0;
     if(!str[0])
	  strncpy(str, default_value, size);

     return(str);
}


char *resolve_tilde(char *path)
{
     wordexp_t we;

     if( (wordexp(path, &we, 0)) == 0 && we.we_wordc == 1)
     {
	  free(path);
	  path = strdup(we.we_wordv[0]);
	  wordfree(&we);
     }

     return(path);
}


void get_auth(void)
{

     auth.hostname = get_interactive("hostname", 64, "localhost");
     auth.port = get_interactive("port", 6, "22");
//     auth.username = get_interactive("username", 20, getenv("USER"));
//     auth.password = get_interactive("password", 20, "");
     auth.username = get_interactive("username", 20, "bert2");
     auth.password = get_interactive("password", 20, "blinko");

     auth.privkey = resolve_tilde(get_interactive("private key filename", 128, "~/.ssh/id_dsa"));
     auth.pubkey = resolve_tilde(get_interactive("public key filename", 128, "~/.ssh/id_dsa.pub"));
     auth.passphrase = get_interactive("passphrase", 256, "");

}


int main(int argc, char **argv)
{

     get_auth();
     if(!strlen(auth.username) || !strlen(auth.password))
     {
	  printf("Not enough authentication info to continue.\n");
	  return(1);
     }

     runtest_methods();
     runtest_auth();
     runtest_forward();

     output_testresults();

     cleanup();

     return(0);
}

