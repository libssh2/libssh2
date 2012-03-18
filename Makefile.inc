CSOURCES = channel.c comp.c crypt.c hostkey.c kex.c mac.c misc.c \
 packet.c publickey.c scp.c session.c sftp.c userauth.c transport.c \
 version.c knownhost.c agent.c pem.c keepalive.c global.c
if OPENSSL
CSOURCES += openssl.c
endif
if LIBGCRYPT
CSOURCES += libgcrypt.c
endif

HHEADERS = libssh2_priv.h transport.h channel.h comp.h mac.h misc.h \
 packet.h userauth.h session.h sftp.h crypto.h
if OPENSSL
HHEADERS += openssl.h
endif
if LIBGCRYPT
HHEADERS += libgcrypt.h
endif
