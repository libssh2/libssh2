# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause
CSOURCES =              \
  agent.c               \
  bcrypt_pbkdf.c        \
  chacha.c              \
  channel.c             \
  cipher-chachapoly.c   \
  comp.c                \
  crypt.c               \
  global.c              \
  hostkey.c             \
  keepalive.c           \
  kex.c                 \
  knownhost.c           \
  libgcrypt.c           \
  mac.c                 \
  mbedtls.c             \
  misc.c                \
  openssl.c             \
  os400qc3.c            \
  packet.c              \
  pem.c                 \
  poly1305.c            \
  publickey.c           \
  scp.c                 \
  session.c             \
  sftp.c                \
  transport.c           \
  userauth.c            \
  userauth_kbd_packet.c \
  version.c             \
  wincng.c

HHEADERS =              \
  chacha.h              \
  channel.h             \
  cipher-chachapoly.h   \
  comp.h                \
  crypto.h              \
  crypto_config.h       \
  libgcrypt.h           \
  libssh2_priv.h        \
  libssh2_setup.h       \
  mac.h                 \
  mbedtls.h             \
  misc.h                \
  openssl.h             \
  os400qc3.h            \
  packet.h              \
  poly1305.h            \
  session.h             \
  sftp.h                \
  transport.h           \
  userauth.h            \
  userauth_kbd_packet.h \
  wincng.h

EXTRA_DIST =            \
  blowfish.c
