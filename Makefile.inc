CSOURCES = channel.c comp.c crypt.c hostkey.c kex.c mac.c misc.c \
 packet.c publickey.c scp.c session.c sftp.c userauth.c transport.c \
 version.c knownhost.c

ifdef LIBGCRYPT
CSOURCES += libgcrypt.c pem.c
else
CSOURCES += openssl.c
endif

HHEADERS = libssh2_priv.h openssl.h libgcrypt.h transport.h channel.h comp.h mac.h misc.h
