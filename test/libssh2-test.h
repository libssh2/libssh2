/*
 * prototest.h
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

#ifndef LIBSSH2_TEST_H
#define LIBSSH2_TEST_H 1

#define MAX_LOGLINE_LEN       256


void log_line(int priority, char *format, ...);
void init_test(char *msg, int num_items);
void increase_progress(void);
void step_successful(void);
void output_testresults(void);
int new_socket(void);
void runtest_methods(void);
void runtest_auth(void);
void runtest_forward(void);



struct authdefs {
     char *hostname;
     char *port;
     char *username;
     char *password;
     char *privkey;
     char *pubkey;
     char *passphrase;
};

struct methodlist {
     int method_type;
     char *description;
     char **list;
     int cursor;
     int done;
};

struct logentry {
     int priority;
     char *logline;
     struct logentry *next;
};

struct logresults {
     char *description;
     int num_steps;
     int success_steps;
     int progress;
     struct logentry *log;
     struct logresults *next;
};


enum {
     ERROR,
     WARNING,
     NORMAL,
     DEBUG
};



#endif
