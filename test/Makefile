LIBS = -L../src -lssh2
CFLAGS = -c -I../include
CC = gcc -Wall -g
OBJS = main.o util.o methods.o auth.o forward.o

all: libssh2-test

libssh2-test: $(OBJS)
	$(CC) -o libssh2-test $(OBJS) $(LIBS)


main.o: main.c libssh2-test.h
util.o: util.c libssh2-test.h
methods.o: methods.c libssh2-test.h
auth.o: auth.c libssh2-test.h
forward.o: forward.c libssh2-test.h

clean:
	rm -f $(OBJS) libssh2-test
