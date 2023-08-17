# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

cmake_minimum_required(VERSION 3.7)

project(test-dependent)

if(NOT DEFINED TEST_INTEGRATION_MODE)
  set(TEST_INTEGRATION_MODE "find_package")
endif()

message(STATUS "TEST_INTEGRATION_MODE: ${TEST_INTEGRATION_MODE}")

if(TEST_INTEGRATION_MODE STREQUAL "find_package")
  find_package(libssh2 REQUIRED CONFIG)
  message(STATUS "libssh2_FOUND: |${libssh2_FOUND}|")
elseif(TEST_INTEGRATION_MODE STREQUAL "add_subdirectory")
  add_subdirectory(libssh2)
elseif(TEST_INTEGRATION_MODE STREQUAL "FetchContent")
  include(FetchContent)
  FetchContent_Declare(libssh2 GIT_REPOSITORY "https://github.com/libssh2/libssh2.git" GIT_TAG "master")
  FetchContent_MakeAvailable(libssh2)
endif()

add_executable(test-dependent-static-ns "test.c")
target_link_libraries(test-dependent-static-ns PRIVATE "libssh2::libssh2_static")

add_executable(test-dependent-shared-ns "test.c")
target_link_libraries(test-dependent-shared-ns PRIVATE "libssh2::libssh2_shared")

# Alias for either shared or static library
add_executable(test-dependent-selected-ns "test.c")
target_link_libraries(test-dependent-selected-ns PRIVATE "libssh2::libssh2")

if(TEST_INTEGRATION_MODE STREQUAL "find_package")

  # Compatibility alias
  add_executable(test-dependent-compat "test.c")
  target_link_libraries(test-dependent-compat PRIVATE "Libssh2::libssh2")

elseif(TEST_INTEGRATION_MODE STREQUAL "add_subdirectory" OR
       TEST_INTEGRATION_MODE STREQUAL "FetchContent")

  add_executable(test-dependent-static-bare "test.c")
  target_link_libraries(test-dependent-static-bare PRIVATE "libssh2_static")

  add_executable(test-dependent-shared-bare "test.c")
  target_link_libraries(test-dependent-shared-bare PRIVATE "libssh2_shared")

  add_executable(test-dependent-selected-bare "test.c")
  target_link_libraries(test-dependent-selected-bare PRIVATE "libssh2")
endif()
