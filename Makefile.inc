CSOURCES = channel.c comp.c crypt.c crypto.c hostkey.c kex.c mac.c misc.c \
  packet.c publickey.c scp.c session.c sftp.c userauth.c transport.c \
  userauth_kbd_packet.c \
  version.c knownhost.c agent.c pem.c keepalive.c global.c \
  bcrypt_pbkdf.c agent_win.c

HHEADERS = libssh2_priv.h libssh2_setup.h transport.h \
  channel.h comp.h mac.h misc.h packet.h userauth.h session.h sftp.h crypto.h \
  agent.h userauth_kbd_packet.h \
  libgcrypt.h mbedtls.h openssl.h os400qc3.h wincng.h
