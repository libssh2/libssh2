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
  warmup
  hostkey
  hostkey_hash
  password_auth_succeeds_with_correct_credentials
  password_auth_fails_with_wrong_password
  password_auth_fails_with_wrong_username
  public_key_auth_fails_with_wrong_key
  public_key_auth_succeeds_with_correct_rsa_key
  public_key_auth_succeeds_with_correct_encrypted_rsa_key
  keyboard_interactive_auth_fails_with_wrong_response
  keyboard_interactive_auth_succeeds_with_correct_response
  agent_forward_succeeds
  read
  )

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR CRYPTO_BACKEND STREQUAL "wolfSSL")
    list(APPEND TESTS
      public_key_auth_succeeds_with_correct_rsa_openssh_key
    )
    if(OPENSSL_VERSION VERSION_GREATER "1.1.0" OR CRYPTO_BACKEND STREQUAL "wolfSSL")
      list(APPEND TESTS
        public_key_auth_succeeds_with_correct_ed25519_key
        public_key_auth_succeeds_with_correct_encrypted_ed25519_key
        public_key_auth_succeeds_with_correct_ed25519_key_from_mem
        public_key_auth_succeeds_with_correct_ecdsa_key
        public_key_auth_succeeds_with_correct_signed_ecdsa_key
        public_key_auth_succeeds_with_correct_signed_rsa_key
       )
    endif()
endif()

if(NOT CRYPTO_BACKEND STREQUAL "mbedTLS")
  list(APPEND TESTS
    public_key_auth_succeeds_with_correct_dsa_key
    )
endif()

add_library(runner STATIC runner.h runner.c openssh_fixture.h openssh_fixture.c session_fixture.h session_fixture.c)
target_include_directories(runner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" ../include)
target_compile_definitions(runner PRIVATE FIXTURE_WORKDIR="${CMAKE_CURRENT_SOURCE_DIR}")

# test building against shared libssh2 lib
if(BUILD_SHARED_LIBS)
  set(test warmup)  # any test will do
  add_executable(test_${test}_shared test_${test}.c)
  target_include_directories(test_${test}_shared PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src")
  target_link_libraries(test_${test}_shared runner ${LIB_SHARED} ${LIBRARIES})
endif()

foreach(test ${TESTS})
  add_executable(test_${test} test_${test}.c)
  list(APPEND TEST_TARGETS test_${test})
  target_include_directories(test_${test} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src")
  target_link_libraries(test_${test} runner ${LIB_STATIC} ${LIBRARIES})

  add_test(
    NAME test_${test} COMMAND $<TARGET_FILE:test_${test}>
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endforeach()

# MAC tests
foreach(test
  hmac-md5
  hmac-md5-96
  hmac-sha1
  hmac-sha1-96
  hmac-sha2-256
  hmac-sha2-512
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

add_executable(test_keyboard_interactive_auth_info_request test_keyboard_interactive_auth_info_request.c ../src/userauth_kbd_packet.c)
target_compile_definitions(test_keyboard_interactive_auth_info_request PRIVATE "${CRYPTO_BACKEND_DEFINE}")
target_include_directories(test_keyboard_interactive_auth_info_request PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" "../src/" "${CRYPTO_BACKEND_INCLUDE_DIR}")
find_program(GCOV_PATH gcov)
set(TGT_OPTIONS -g --coverage -fprofile-abs-path)
if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
        set(TGT_OPTIONS -g --coverage)
endif()
if(CMAKE_COMPILER_IS_GNUCC AND GCOV_PATH)
  target_compile_options(test_keyboard_interactive_auth_info_request BEFORE PRIVATE
    ${TGT_OPTIONS})
  target_link_libraries(test_keyboard_interactive_auth_info_request ${LIBRARIES} ${LIB_STATIC} gcov)
else()
  target_link_libraries(test_keyboard_interactive_auth_info_request ${LIBRARIES} ${LIB_STATIC})
endif()
add_test(
  NAME test_keyboard_interactive_auth_info_request COMMAND $<TARGET_FILE:test_keyboard_interactive_auth_info_request>
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

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
