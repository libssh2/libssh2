# Copyright (C) The libssh2 project and its contributors.
# SPDX-License-Identifier: BSD-3-Clause

option(LIBSSH2_USE_PKGCONFIG "Enable pkg-config to detect @PROJECT_NAME@ dependencies. Default: @LIBSSH2_USE_PKGCONFIG@"
  "@LIBSSH2_USE_PKGCONFIG@")

if(CMAKE_VERSION VERSION_LESS @CMAKE_MINIMUM_REQUIRED_VERSION@)
  message(STATUS "@PROJECT_NAME@: @PROJECT_NAME@-specific Find modules require "
    "CMake @CMAKE_MINIMUM_REQUIRED_VERSION@ or upper, found: ${CMAKE_VERSION}.")
endif()

include(CMakeFindDependencyMacro)

set(_libssh2_cmake_module_path_save ${CMAKE_MODULE_PATH})
list(PREPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR})

set(_libssh2_libs "")
if("@CRYPTO_BACKEND@" STREQUAL "OpenSSL")
  find_dependency(OpenSSL)
elseif("@CRYPTO_BACKEND@" STREQUAL "wolfSSL")
  find_dependency(WolfSSL)
  list(APPEND _libssh2_libs libssh2::wolfssl)
elseif("@CRYPTO_BACKEND@" STREQUAL "Libgcrypt")
  find_dependency(Libgcrypt)
  list(APPEND _libssh2_libs libssh2::libgcrypt)
elseif("@CRYPTO_BACKEND@" STREQUAL "mbedTLS")
  find_dependency(MbedTLS)
  list(APPEND _libssh2_libs libssh2::mbedcrypto)
endif()

if(@ZLIB_FOUND@)
  find_dependency(ZLIB)
endif()

set(CMAKE_MODULE_PATH ${_libssh2_cmake_module_path_save})

include("${CMAKE_CURRENT_LIST_DIR}/@PROJECT_NAME@-targets.cmake")

# Alias for either shared or static library
if(NOT TARGET @PROJECT_NAME@::@LIB_NAME@)
  add_library(@PROJECT_NAME@::@LIB_NAME@ ALIAS @PROJECT_NAME@::@LIB_SELECTED@)
endif()

# Compatibility alias
if(NOT TARGET Libssh2::@LIB_NAME@)
  add_library(Libssh2::@LIB_NAME@ ALIAS @PROJECT_NAME@::@LIB_SELECTED@)
endif()
