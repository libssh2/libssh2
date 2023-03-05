#!/bin/sh

for test in \
  hmac-md5 \
  hmac-md5-96 \
  hmac-sha1 \
  hmac-sha1-96 \
  hmac-sha2-256 \
  hmac-sha2-512 \
  ; do
  FIXTURE_TEST_MAC="${test}" ./test_read
done

for test in \
  3des-cbc \
  aes128-cbc \
  aes128-ctr \
  aes192-cbc \
  aes192-ctr \
  aes256-cbc \
  aes256-ctr \
  rijndael-cbc@lysator.liu.se \
  ; do
  FIXTURE_TEST_CRYPT="${test}" ./test_read
done
