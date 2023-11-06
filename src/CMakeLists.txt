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

set(LIBSSH2_SOVERSION 1)
set(LIBSSH2_LIBVERSION 1.0.1)

if(CRYPTO_BACKEND)
  list(APPEND PRIVATE_COMPILE_DEFINITIONS ${CRYPTO_BACKEND_DEFINE})
  list(APPEND PRIVATE_INCLUDE_DIRECTORIES ${CRYPTO_BACKEND_INCLUDE_DIR})
  add_feature_info("Crypto backend" ON "${CRYPTO_BACKEND}")
else()
  message(FATAL_ERROR "No suitable cryptography backend found.")
endif()

## Options

option(CLEAR_MEMORY "Enable clearing of memory before being freed" ON)
if(NOT CLEAR_MEMORY)
  list(APPEND libssh2_DEFINITIONS "LIBSSH2_NO_CLEAR_MEMORY")
endif()

option(ENABLE_ZLIB_COMPRESSION "Use zlib for compression" OFF)
add_feature_info(Compression ENABLE_ZLIB_COMPRESSION
  "using zlib for compression")
if(ENABLE_ZLIB_COMPRESSION)
  find_package(ZLIB REQUIRED)

  list(APPEND libssh2_INCLUDE_DIRS ${ZLIB_INCLUDE_DIRS})
  list(APPEND LIBRARIES ${ZLIB_LIBRARIES})
  list(APPEND LIBSSH2_PC_LIBS_PRIVATE "-lz")
  list(APPEND LIBSSH2_PC_REQUIRES_PRIVATE "zlib")
  if(ZLIB_FOUND)
    list(APPEND libssh2_DEFINITIONS "LIBSSH2_HAVE_ZLIB")
  endif()
endif()

list(APPEND LIBRARIES ${SOCKET_LIBRARIES})

if(WIN32)
  list(APPEND LIBSSH2_PC_LIBS_PRIVATE "-lws2_32")
endif()

# to find generated header
list(APPEND libssh2_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR})

if(MSVC)
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi /Od")
  set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} /DEBUG")
endif()

## Sources

include(GNUInstallDirs)
transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
# Get 'CSOURCES' and 'HHEADERS' variables
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
set(SOURCES ${CSOURCES} ${HHEADERS})

## Library definition

# Ensure that the static library and import library filenames are different,
# when building both static and shared library. On Windows, with certain
# toolchains (e.g. MSVC) these libraries get the same by default, overwriting
# each other. MinGW is not affected.
if(WIN32 AND BUILD_STATIC_LIBS AND BUILD_SHARED_LIBS AND
   NOT STATIC_LIB_SUFFIX AND NOT IMPORT_LIB_SUFFIX AND
   CMAKE_STATIC_LIBRARY_SUFFIX STREQUAL CMAKE_IMPORT_LIBRARY_SUFFIX)
  set(STATIC_LIB_SUFFIX "_static")
endif()

# we want it to be called libssh2 on all platforms
if(BUILD_STATIC_LIBS)
  list(APPEND libssh2_export ${LIB_STATIC})
  add_library(${LIB_STATIC} STATIC ${SOURCES})
  add_library(${PROJECT_NAME}::${LIB_STATIC} ALIAS ${LIB_STATIC})
  target_compile_definitions(${LIB_STATIC} PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} ${libssh2_DEFINITIONS})
  target_link_libraries(${LIB_STATIC} PRIVATE ${LIBRARIES})
  set_target_properties(${LIB_STATIC} PROPERTIES
    PREFIX "" OUTPUT_NAME "libssh2" SOVERSION "${LIBSSH2_SOVERSION}" VERSION "${LIBSSH2_LIBVERSION}"
    SUFFIX "${STATIC_LIB_SUFFIX}${CMAKE_STATIC_LIBRARY_SUFFIX}")

  target_include_directories(${LIB_STATIC}
    PRIVATE "${PROJECT_SOURCE_DIR}/include/" ${libssh2_INCLUDE_DIRS} ${PRIVATE_INCLUDE_DIRECTORIES}
    PUBLIC
      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>")
endif()
if(BUILD_SHARED_LIBS)
  list(APPEND libssh2_export ${LIB_SHARED})
  add_library(${LIB_SHARED} SHARED ${SOURCES})
  add_library(${PROJECT_NAME}::${LIB_SHARED} ALIAS ${LIB_SHARED})
  if(WIN32)
    set_property(TARGET ${LIB_SHARED} APPEND PROPERTY SOURCES "libssh2.rc")
  endif()
  target_compile_definitions(${LIB_SHARED} PRIVATE ${PRIVATE_COMPILE_DEFINITIONS} ${libssh2_DEFINITIONS} ${LIB_SHARED_DEFINITIONS})
  target_compile_options(${LIB_SHARED} PRIVATE ${LIB_SHARED_C_FLAGS})
  target_link_libraries(${LIB_SHARED} PRIVATE ${LIBRARIES})
  set_target_properties(${LIB_SHARED} PROPERTIES
    PREFIX "" OUTPUT_NAME "libssh2" SOVERSION "${LIBSSH2_SOVERSION}" VERSION "${LIBSSH2_LIBVERSION}"
    IMPORT_PREFIX "" IMPORT_SUFFIX "${IMPORT_LIB_SUFFIX}${CMAKE_IMPORT_LIBRARY_SUFFIX}"
    POSITION_INDEPENDENT_CODE ON)

  target_include_directories(${LIB_SHARED}
    PRIVATE "${PROJECT_SOURCE_DIR}/include/" ${libssh2_INCLUDE_DIRS} ${PRIVATE_INCLUDE_DIRECTORIES}
    PUBLIC
      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>"
      "$<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_INCLUDEDIR}>")
endif()

add_library(${PROJECT_NAME}::${LIB_NAME} ALIAS ${LIB_SELECTED})
add_library(${LIB_NAME} ALIAS ${LIB_SELECTED})

## Installation

install(FILES
  "${PROJECT_SOURCE_DIR}/include/libssh2.h"
  "${PROJECT_SOURCE_DIR}/include/libssh2_publickey.h"
  "${PROJECT_SOURCE_DIR}/include/libssh2_sftp.h"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(BUILD_STATIC_LIBS)
  install(TARGETS ${LIB_STATIC}
    EXPORT "${PROJECT_NAME}-targets"
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()
if(BUILD_SHARED_LIBS)
  install(TARGETS ${LIB_SHARED}
    EXPORT "${PROJECT_NAME}-targets"
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

  list(APPEND _RUNTIME_DEPENDENCIES $<TARGET_FILE:${LIB_SHARED}>)
endif()

set(RUNTIME_DEPENDENCIES ${_RUNTIME_DEPENDENCIES} CACHE INTERNAL
    "Files that must be in the same directory as the executables at runtime.")

# Package config

## During package installation, install libssh2-targets.cmake
install(EXPORT "${PROJECT_NAME}-targets"
  NAMESPACE "${PROJECT_NAME}::"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

## During build, register directly from build tree
# create libssh2-targets.cmake
export(TARGETS ${libssh2_export} NAMESPACE "${PROJECT_NAME}::" FILE "${PROJECT_NAME}-targets.cmake")
export(PACKAGE ${PROJECT_NAME})  # register it

# Generate libssh2-config.cmake into build tree and install it
configure_file("${PROJECT_SOURCE_DIR}/cmake/libssh2-config.cmake.in" "${PROJECT_NAME}-config.cmake" @ONLY)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")

## Export a .pc file for client projects not using CMaek
if(LIBSSH2_PC_REQUIRES_PRIVATE)
  string(REPLACE ";" "," LIBSSH2_PC_REQUIRES_PRIVATE "${LIBSSH2_PC_REQUIRES_PRIVATE}")
endif()
if(LIBSSH2_PC_LIBS_PRIVATE)
  list(REMOVE_DUPLICATES LIBSSH2_PC_LIBS_PRIVATE)
  string(REPLACE ";" " " LIBSSH2_PC_LIBS_PRIVATE "${LIBSSH2_PC_LIBS_PRIVATE}")
endif()
# merge the pkg-config private fields into public ones when static-only
if(BUILD_SHARED_LIBS)
  set(LIBSSH2_PC_REQUIRES "")
  set(LIBSSH2_PC_LIBS "")
else()
  set(LIBSSH2_PC_REQUIRES "${LIBSSH2_PC_REQUIRES_PRIVATE}")
  set(LIBSSH2_PC_LIBS "${LIBSSH2_PC_LIBS_PRIVATE}")
endif()
set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
set(includedir "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
configure_file("${PROJECT_SOURCE_DIR}/libssh2.pc.in" "libssh2.pc" @ONLY)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/libssh2.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

#

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake"
  VERSION "${LIBSSH2_VERSION_MAJOR}.${LIBSSH2_VERSION_MINOR}.${LIBSSH2_VERSION_PATCH}"
  COMPATIBILITY SameMajorVersion)
install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
