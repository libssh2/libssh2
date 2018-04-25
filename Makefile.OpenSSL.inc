CRYPTO_CSOURCES = openssl.c curve25519.c 
CRYPTO_HHEADERS = openssl.h curve25519.h curve25519_priv.h
CRYPTO_LTLIBS = $(LTLIBSSL)
