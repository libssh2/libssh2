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

transform_makefile_inc("Makefile.am" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.am.cmake")
# Get 'DOCKER_TESTS', 'STANDALONE_TESTS', 'SSHD_TESTS', 'librunner_la_SOURCES' variables
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.am.cmake)

if(CMAKE_COMPILER_IS_GNUCC)
  find_program(GCOV_PATH gcov)
  if(GCOV_PATH)
    set(GCOV_OPTIONS -g --coverage)
    if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
      set(GCOV_OPTIONS "${GCOV_OPTIONS} -fprofile-abs-path")
    endif()
  endif()
endif()

find_program(SH_EXECUTABLE sh)
mark_as_advanced(SH_EXECUTABLE)
if(SH_EXECUTABLE)
  find_program(SSHD_EXECUTABLE sshd)
  mark_as_advanced(SSHD_EXECUTABLE)

  add_test(NAME mansyntax COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/mansyntax.sh")
endif()

add_library(runner STATIC ${librunner_la_SOURCES})
target_compile_definitions(runner PRIVATE "${CRYPTO_BACKEND_DEFINE}")
target_include_directories(runner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" ../src ../include "${CRYPTO_BACKEND_INCLUDE_DIR}")
target_compile_definitions(runner PRIVATE FIXTURE_WORKDIR="${CMAKE_CURRENT_SOURCE_DIR}")

# These programs use internal libssh2 functions so they need to be statically
# linked against libssh2
set(TESTS_WITH_LIB_STATIC
  test_auth_keyboard_info_request
  test_hostkey
  test_simple
)

foreach(test ${DOCKER_TESTS} ${STANDALONE_TESTS} ${SSHD_TESTS})
  # We support the same target as both Docker and SSHD test. Build those just once.
  if(NOT TARGET ${test})
    add_executable(${test} ${test}.c)
    target_compile_definitions(${test} PRIVATE "${CRYPTO_BACKEND_DEFINE}")
    target_include_directories(${test} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" ../src ../include "${CRYPTO_BACKEND_INCLUDE_DIR}")

    # build a single test with gcov
    if(GCOV_PATH AND test STREQUAL test_auth_keyboard_info_request)
      target_compile_options(${test} BEFORE PRIVATE ${GCOV_OPTIONS})
      target_link_libraries(${test} runner ${LIB_STATIC} ${LIBRARIES} gcov)
    elseif(";${TESTS_WITH_LIB_STATIC};" MATCHES ";${test};")
      target_link_libraries(${test} runner ${LIB_STATIC} ${LIBRARIES})
    else()
      target_link_libraries(${test} runner ${LIB_SELECTED} ${LIBRARIES})
    endif()

    list(APPEND TEST_TARGETS ${test})
  endif()
endforeach()

foreach(test ${DOCKER_TESTS} ${STANDALONE_TESTS})
  add_test(NAME ${test} COMMAND $<TARGET_FILE:${test}>
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endforeach()

if(SSHD_EXECUTABLE)
  # On Windows / AppVeyor CI, subsequent tests are broken:
  #   'libssh2_session_handshake failed (-43): Failed getting banner'
  if(WIN32)
    list(GET SSHD_TESTS 0 SSHD_TESTS)
  endif()
  foreach(test ${SSHD_TESTS})
    set(testname sshd-${test})
    add_test(NAME ${testname} COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/sshd_fixture.sh $<TARGET_FILE:${test}>")
    set_property(TEST ${testname} APPEND PROPERTY ENVIRONMENT "SSHD=${SSHD_EXECUTABLE}")
  endforeach()
endif()

# CRYPT/MAC algo tests
file(READ "test_read_algos.txt" ALGO_TESTS)
string(REGEX REPLACE "\\\n" ";" ALGO_TESTS ${ALGO_TESTS})
foreach(test ${ALGO_TESTS})
  set(testname test_read-${test})
  add_test(NAME ${testname} COMMAND "$<TARGET_FILE:test_read>")
  if(test MATCHES "mac-")
    set_property(TEST ${testname} APPEND PROPERTY ENVIRONMENT "FIXTURE_TEST_MAC=${test}")
  else()
    set_property(TEST ${testname} APPEND PROPERTY ENVIRONMENT "FIXTURE_TEST_CRYPT=${test}")
  endif()
endforeach()

add_custom_target(coverage
  COMMAND gcovr -r "${CMAKE_SOURCE_DIR}" --exclude tests/*
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/coverage/"
  COMMAND gcovr -r "${CMAKE_SOURCE_DIR}" --exclude tests/* --html-details --output "${CMAKE_CURRENT_BINARY_DIR}/coverage/index.html")

add_custom_target(clean-coverage
  COMMAND rm -rf "${CMAKE_CURRENT_BINARY_DIR}/coverage/")

add_target_to_copy_dependencies(
  TARGET copy_test_dependencies
  DEPENDENCIES ${RUNTIME_DEPENDENCIES}
  BEFORE_TARGETS ${TEST_TARGETS})
