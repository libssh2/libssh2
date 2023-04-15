# Copyright (c) 2014-2016 Alexander Lamaison <alexander.lamaison@gmail.com>
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials
#   provided with the distribution.
#
#   Neither the name of the copyright holder nor the names
#   of any other contributors may be used to endorse or
#   promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.

include(CopyRuntimeDependencies)

list(APPEND LIBRARIES ${SOCKET_LIBRARIES})

add_definitions(-DHAVE_CONFIG_H)

set(TESTS
  simple
  ssh2
  test_warmup    # keep this the first test
  test_hostkey
  test_hostkey_hash
  test_password_auth_succeeds_with_correct_credentials
  test_password_auth_fails_with_wrong_password
  test_password_auth_fails_with_wrong_username
  test_public_key_auth_fails_with_wrong_key
  test_public_key_auth_succeeds_with_correct_rsa_key
  test_public_key_auth_succeeds_with_correct_encrypted_rsa_key
  test_keyboard_interactive_auth_fails_with_wrong_response
  test_keyboard_interactive_auth_succeeds_with_correct_response
  test_keyboard_interactive_auth_info_request
  test_agent_forward_succeeds
  test_read
)

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR CRYPTO_BACKEND STREQUAL "wolfSSL")
  list(APPEND TESTS
    test_public_key_auth_succeeds_with_correct_rsa_openssh_key
  )
  if(OPENSSL_VERSION VERSION_GREATER "1.1.0" OR CRYPTO_BACKEND STREQUAL "wolfSSL")
    list(APPEND TESTS
      test_public_key_auth_succeeds_with_correct_ed25519_key
      test_public_key_auth_succeeds_with_correct_encrypted_ed25519_key
      test_public_key_auth_succeeds_with_correct_ed25519_key_from_mem
      test_public_key_auth_succeeds_with_correct_ecdsa_key
      test_public_key_auth_succeeds_with_correct_signed_ecdsa_key
      test_public_key_auth_succeeds_with_correct_signed_rsa_key
    )
  endif()
endif()

if(NOT CRYPTO_BACKEND STREQUAL "mbedTLS")
  list(APPEND TESTS
    test_public_key_auth_succeeds_with_correct_dsa_key
  )
endif()

add_library(runner STATIC runner.h runner.c openssh_fixture.h openssh_fixture.c session_fixture.h session_fixture.c)
target_include_directories(runner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" ../src ../include)
target_compile_definitions(runner PRIVATE FIXTURE_WORKDIR="${CMAKE_CURRENT_SOURCE_DIR}")

# test building against shared libssh2 lib
if(BUILD_SHARED_LIBS)
  foreach(test ssh2)
    add_executable(${test}_shared ${test}.c)
    target_include_directories(${test}_shared PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" ../src)
    target_link_libraries(${test}_shared ${LIB_SHARED} ${LIBRARIES})
  endforeach()
endif()

if(CMAKE_COMPILER_IS_GNUCC)
  find_program(GCOV_PATH gcov)
  if(GCOV_PATH)
    set(GCOV_OPTIONS -g --coverage)
    if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
      set(GCOV_OPTIONS "${GCOV_OPTIONS} -fprofile-abs-path")
    endif()
  endif()
endif()

foreach(test ${TESTS})
  add_executable(${test} ${test}.c)
  target_compile_definitions(${test} PRIVATE "${CRYPTO_BACKEND_DEFINE}")
  target_include_directories(${test} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" ../src "${CRYPTO_BACKEND_INCLUDE_DIR}")

  # build a single test with gcov
  if(GCOV_PATH AND test STREQUAL test_keyboard_interactive_auth_info_request)
    target_compile_options(${test} BEFORE PRIVATE ${GCOV_OPTIONS})
    target_link_libraries(${test} runner ${LIB_STATIC} ${LIBRARIES} gcov)
  else()
    target_link_libraries(${test} runner ${LIB_STATIC} ${LIBRARIES})
  endif()

  if(test MATCHES "^test_")
    list(APPEND TEST_TARGETS ${test})
    add_test(
      NAME ${test} COMMAND $<TARGET_FILE:${test}>
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
  endif()
endforeach()

# MAC tests
foreach(test
  hmac-md5
  hmac-md5-96
  hmac-sha1
  hmac-sha1-96
  hmac-sha2-256
  hmac-sha2-512
  hmac-sha1-etm@openssh.com
  hmac-sha2-256-etm@openssh.com
  hmac-sha2-512-etm@openssh.com
)
  add_test(NAME test_${test} COMMAND "$<TARGET_FILE:test_read>")
  set_tests_properties(test_${test} PROPERTIES ENVIRONMENT "FIXTURE_TEST_MAC=${test}")
endforeach()

# CRYPT tests
set(TESTS
  aes128-ctr
  aes192-ctr
  aes256-ctr
)
# Due to a bug with mbedTLS support, these crypt methods fail. Until that bug
# is fixed, don't run them there to avoid this known issue causing red tests.
# See https://github.com/libssh2/libssh2/issues/793
if(NOT CRYPTO_BACKEND STREQUAL "mbedTLS")
  list(APPEND TESTS
    3des-cbc
    aes128-cbc
    aes192-cbc
    aes256-cbc
    rijndael-cbc@lysator.liu.se
  )
endif()
foreach(test ${TESTS})
  add_test(NAME test_${test} COMMAND "$<TARGET_FILE:test_read>")
  set_tests_properties(test_${test} PROPERTIES ENVIRONMENT "FIXTURE_TEST_CRYPT=${test}")
endforeach()

add_custom_target(coverage
  COMMAND gcovr -r "${CMAKE_SOURCE_DIR}" --exclude tests/*
  COMMAND mkdir -p "${CMAKE_CURRENT_BINARY_DIR}/coverage/"
  COMMAND gcovr -r "${CMAKE_SOURCE_DIR}" --exclude tests/* --html-details --output "${CMAKE_CURRENT_BINARY_DIR}/coverage/index.html")

add_custom_target(clean-coverage
  COMMAND rm -rf "${CMAKE_CURRENT_BINARY_DIR}/coverage/")

add_target_to_copy_dependencies(
  TARGET copy_test_dependencies
  DEPENDENCIES ${RUNTIME_DEPENDENCIES}
  BEFORE_TARGETS ${TEST_TARGETS})


# TODO convert mansyntax.sh into CMake script.
# XXX Just because we can find all three programs, doesn't mean sh can
# find man and grep
find_program(SH_EXECUTABLE sh)
find_program(MAN_EXECUTABLE man)
find_program(GREP_EXECUTABLE grep)
mark_as_advanced(SH_EXECUTABLE MAN_EXECUTABLE GREP_EXECUTABLE)
if(SH_EXECUTABLE AND MAN_EXECUTABLE AND GREP_EXECUTABLE)
  set(cmd "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
  set(cmd "${cmd} ${CMAKE_CURRENT_SOURCE_DIR}/mansyntax.sh")
  add_test(mansyntax ${SH_EXECUTABLE} -c "${cmd}")
endif()
