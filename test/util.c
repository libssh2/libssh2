/*
 * util.c
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>

#include <libssh2.h>
#include "libssh2-test.h"


extern struct addrinfo *hostai, *cur_ai;
struct logresults *testlogs = NULL, *cur_testlog;
struct logentry *logfile = NULL, *cur_logentry;

extern struct authdefs auth;
extern char *progress_message;
extern int progress, progress_max;


struct loglevel {
     int priority;
     char *descr;
} loglevels[] = {
     {   ERROR, "ERROR" },
     { WARNING, "WARNING" },
     {  NORMAL, "NORMAL" },
     {   DEBUG, "DEBUG" }
};



void log_line(int priority, char *format, ...)
{
     va_list args;
     struct logentry *entry;
     char line[MAX_LOGLINE_LEN];

     va_start(args, format);
     vsnprintf(line, MAX_LOGLINE_LEN, format, args);
     va_end(args);

     entry = malloc(sizeof(struct logentry));
     entry->priority = priority;
     entry->logline = malloc(strlen(line)+1);
     strcpy(entry->logline, line);
     entry->next = NULL;

     if(!cur_testlog->log)
	  cur_testlog->log = entry;
     else
	  cur_logentry->next = entry;

     cur_logentry = entry;

}


void init_test(char *msg, int num_items)
{
     struct logresults *newtest;

     newtest = malloc(sizeof(struct logresults));
     newtest->description = msg;
     newtest->num_steps = num_items;
     newtest->success_steps = 0;
     newtest->progress = 0;
     newtest->log = NULL;
     newtest->next = NULL;

     if(!testlogs)
	  testlogs = newtest;
     else
	  cur_testlog->next = newtest;

     cur_testlog = newtest;

}


void increase_progress(void)
{

     cur_testlog->progress++;

     printf("Testing %s... %3d/%d\r", cur_testlog->description, cur_testlog->progress, cur_testlog->num_steps);
     fflush(stdout);

}


void step_successful(void)
{

     cur_testlog->success_steps++;

}


void output_testresults(void)
{
     struct logresults *test;
     struct logentry *logfile;
     int total_steps, total_success;

     printf("\nTest results\n============\n");

     total_steps = 0;
     total_success = 0;
     test = testlogs;
     while(test)
     {
	  total_steps += test->num_steps;
	  total_success += test->success_steps;
	  printf("Test: %s (%d/%d)\n", test->description, test->success_steps, test->num_steps);
	  logfile = test->log;
	  while(logfile)
	  {
	       printf("  %s", logfile->logline);
	       logfile = logfile->next;
	  }

	  test = test->next;
     }

     printf("%d/%d steps successful\n", total_success, total_steps);

}


int new_socket(void)
{
     int sock, res;
     struct addrinfo hints, *ai;

     memset(&hints, 0, sizeof(struct addrinfo));
     hints.ai_family = PF_INET;
     hints.ai_socktype = SOCK_STREAM;

     if(!hostai)
     {
	  res = getaddrinfo(auth.hostname, auth.port, &hints, &hostai);
	  if(res)
	  {
	       printf("unable to resolve %s: %s\n", auth.hostname, gai_strerror(res));
	       return(-1);
	  }
     }

     sock = 0;
     ai = hostai;
     while(ai)
     {
	  sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	  if(sock > 0)
	  {
	       res = connect(sock, ai->ai_addr, ai->ai_addrlen);
	       if(res == 0)
		    break;

	       close(sock);
	       sock = 0;
	  }
	  ai = ai->ai_next;
     }

     if(!sock)
     {
	  printf("unable to connect: %s\n", strerror(errno));
	  close(sock);
	  sock = -1;
     }

     cur_ai = ai;

     return(sock);
}


