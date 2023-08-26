# Copyright (C) Alexander Lamaison <alexander.lamaison@gmail.com>
# Copyright (C) Viktor Szakats
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
#
# SPDX-License-Identifier: BSD-3-Clause

include(CopyRuntimeDependencies)

list(APPEND LIBRARIES ${SOCKET_LIBRARIES})

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
# Get 'DOCKER_TESTS', 'DOCKER_TESTS_STATIC', 'STANDALONE_TESTS', 'STANDALONE_TESTS_STATIC', 'SSHD_TESTS',
# 'librunner_la_SOURCES' variables
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
list(APPEND DOCKER_TESTS ${DOCKER_TESTS_STATIC})
list(APPEND STANDALONE_TESTS ${STANDALONE_TESTS_STATIC})

if(CMAKE_COMPILER_IS_GNUCC)
  find_program(GCOV_PATH gcov)
  if(GCOV_PATH)
    set(GCOV_CFLAGS "-g" "--coverage")
    if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
      set(GCOV_CFLAGS "${GCOV_CFLAGS} -fprofile-abs-path")
    endif()
  endif()
endif()

option(RUN_SSHD_TESTS "Run tests requiring sshd" ON)

find_program(SH_EXECUTABLE sh)
mark_as_advanced(SH_EXECUTABLE)
if(SH_EXECUTABLE)
  if(RUN_SSHD_TESTS)
    find_program(SSHD_EXECUTABLE sshd)
    mark_as_advanced(SSHD_EXECUTABLE)
  endif()

  add_test(NAME mansyntax COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/mansyntax.sh")
endif()

add_library(runner STATIC ${librunner_la_SOURCES})
target_compile_definitions(runner PRIVATE "${CRYPTO_BACKEND_DEFINE}")
target_include_directories(runner PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" "../src" "../include" "${CRYPTO_BACKEND_INCLUDE_DIR}")

foreach(test IN LISTS DOCKER_TESTS STANDALONE_TESTS SSHD_TESTS)
  if(NOT ";${DOCKER_TESTS_STATIC};${STANDALONE_TESTS_STATIC};" MATCHES ";${test};")
    set(LIB_FOR_TESTS ${LIB_SELECTED})
  elseif(TARGET ${LIB_STATIC})
    set(LIB_FOR_TESTS ${LIB_STATIC})
  else()
    unset(LIB_FOR_TESTS)
    message(STATUS "Skip test requiring static libssh2 lib: ${test}")
  endif()

  # We support the same target as both Docker and SSHD test. Build those just once.
  # Skip building tests that require the static lib when the static lib is disabled.
  if(NOT TARGET ${test} AND LIB_FOR_TESTS)
    add_executable(${test} "${test}.c")
    target_compile_definitions(${test} PRIVATE "${CRYPTO_BACKEND_DEFINE}")
    target_include_directories(${test} PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/../src" "../src" "../include" "${CRYPTO_BACKEND_INCLUDE_DIR}")
    set_target_properties(${test} PROPERTIES UNITY_BUILD OFF)

    # build a single test with gcov
    if(GCOV_PATH AND test STREQUAL "test_auth_keyboard_info_request" AND TARGET ${LIB_STATIC})
      target_compile_options(${test} BEFORE PRIVATE ${GCOV_CFLAGS})
      target_link_libraries(${test} runner ${LIB_FOR_TESTS} ${LIBRARIES} "gcov")
    else()
      target_link_libraries(${test} runner ${LIB_FOR_TESTS} ${LIBRARIES})
    endif()

    list(APPEND TEST_TARGETS ${test})
  endif()
endforeach()

option(RUN_DOCKER_TESTS "Run tests requiring Docker" ON)

if(RUN_DOCKER_TESTS)
  foreach(test IN LISTS DOCKER_TESTS)
    if(TARGET ${test})
      add_test(NAME ${test} COMMAND "$<TARGET_FILE:${test}>")
      set_property(TEST ${test} APPEND PROPERTY ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
    endif()
  endforeach()
endif()

foreach(test IN LISTS STANDALONE_TESTS)
  if(TARGET ${test})
    add_test(NAME ${test} COMMAND "$<TARGET_FILE:${test}>")
    set_property(TEST ${test} APPEND PROPERTY ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
  endif()
endforeach()

if(RUN_SSHD_TESTS AND SSHD_EXECUTABLE)
  unset(sshd_test_targets)
  foreach(test IN LISTS SSHD_TESTS)
    if(TARGET ${test})
      set(sshd_test_targets "${sshd_test_targets} $<TARGET_FILE:${test}>")
    endif()
  endforeach()

  if(sshd_test_targets)
    add_test(NAME test_sshd COMMAND ${SH_EXECUTABLE} -c "${CMAKE_CURRENT_SOURCE_DIR}/test_sshd.test ${sshd_test_targets}")
    set_property(TEST test_sshd APPEND PROPERTY ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
    set_property(TEST test_sshd APPEND PROPERTY ENVIRONMENT "SSHD=${SSHD_EXECUTABLE}")
  endif()
endif()

if(RUN_DOCKER_TESTS)
  # CRYPT/MAC algo tests
  file(READ "test_read_algos.txt" ALGO_TESTS)
  string(REGEX REPLACE "\\\n" ";" ALGO_TESTS ${ALGO_TESTS})
  foreach(test IN LISTS ALGO_TESTS)
    if(test)
      set(testname "test_read-${test}")
      add_test(NAME ${testname} COMMAND "$<TARGET_FILE:test_read>")
      set_property(TEST ${testname} APPEND PROPERTY ENVIRONMENT "srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
      if(test MATCHES "mac-")
        set_property(TEST ${testname} APPEND PROPERTY ENVIRONMENT "FIXTURE_TEST_MAC=${test}")
      else()
        set_property(TEST ${testname} APPEND PROPERTY ENVIRONMENT "FIXTURE_TEST_CRYPT=${test}")
      endif()
    endif()
  endforeach()
endif()

add_custom_target(coverage
  COMMAND gcovr --root "${PROJECT_SOURCE_DIR}" --exclude tests/*
  COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/coverage/"
  COMMAND gcovr --root "${PROJECT_SOURCE_DIR}" --exclude tests/* --html-details --output "${CMAKE_CURRENT_BINARY_DIR}/coverage/index.html")

add_custom_target(clean-coverage
  COMMAND rm -rf "${CMAKE_CURRENT_BINARY_DIR}/coverage/")

add_target_to_copy_dependencies(
  TARGET copy_test_dependencies
  DEPENDENCIES ${RUNTIME_DEPENDENCIES}
  BEFORE_TARGETS ${TEST_TARGETS})
