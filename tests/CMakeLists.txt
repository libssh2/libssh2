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

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CopyRuntimeDependencies)
include(SocketLibraries)

## Platform checks
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(sys/param.h HAVE_SYS_PARAM_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(windows.h HAVE_WINDOWS_H)
check_include_files(winsock2.h HAVE_WINSOCK2_H)
check_include_files(netinet/in.h HAVE_NETINET_IN_H)
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/clar_libssh2_config_cmake.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/clar_libssh2_config.h")
append_needed_socket_libraries(LIBRARIES)

## Cryptography backend choice

set(CRYPTO_BACKEND
  ""
  CACHE
  STRING
  "The backend to use for cryptography: OpenSSL, Libgcrypt or WinCNG, mbedTLS
or empty to try any available")

# If the crypto backend was given, rather than searching for the first
# we are able to find, the find_package commands must abort configuration
# and report to the user.
if(CRYPTO_BACKEND)
  set(SPECIFIC_CRYPTO_REQUIREMENT REQUIRED)
endif()

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)

  find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(OPENSSL_FOUND)
    set(CRYPTO_BACKEND "OpenSSL")
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "Libgcrypt" OR NOT CRYPTO_BACKEND)

  find_package(Libgcrypt ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(LIBGCRYPT_FOUND)
    set(CRYPTO_BACKEND "Libgcrypt")
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "WinCNG" OR NOT CRYPTO_BACKEND)

  # The check actually compiles the header.  This requires windows.h.
  check_include_files("windows.h;bcrypt.h" HAVE_BCRYPT_H)

  if(HAVE_BCRYPT_H)
    set(CRYPTO_BACKEND "WinCNG")
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "mbedTLS" OR NOT CRYPTO_BACKEND)

  find_package(mbedTLS ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(MBEDTLS_FOUND)
    set(CRYPTO_BACKEND "mbedTLS")
  endif()
endif()

# Turn around and grab our parent's COMPILE_DEFINITIONS so we use its #defines
get_target_property(LIBSSH2_DEFINES libssh2-object COMPILE_DEFINITIONS)
get_target_property(LIBSSH2_INCLUDES libssh2-object INCLUDE_DIRECTORIES)
get_target_property(LIBSSH2_LIBS libssh2 LINK_LIBRARIES)
get_target_property(LIBSSH2_SRC libssh2-object SOURCES)

find_package(PythonInterp)

if(NOT PYTHONINTERP_FOUND)
  message(FATAL_ERROR "Could not find a python interpreter, which is needed to "
  "build the tests. Make sure python is available, or pass -DBUILD_TESTING=OFF to "
  "skip building the tests")
endif()

set(CLAR_FIXTURES "${CMAKE_CURRENT_SOURCE_DIR}/resources/")
set(CLAR_TESTCASES "${CMAKE_CURRENT_SOURCE_DIR}/testcases/")
set(CLAR_PATH "${CMAKE_CURRENT_SOURCE_DIR}")
ADD_DEFINITIONS(-DCLAR_FIXTURE_PATH=\"${CLAR_FIXTURES}\")
ADD_DEFINITIONS(-DCLAR_TMPDIR=\"libssh2_tests\")

file(GLOB_RECURSE SRC_TEST ${CLAR_PATH}/*/*.c ${CLAR_PATH}/*/*.h)

set(SRC_CLAR clar.c clar_libssh2.c clar_libssh2.h runner.c clar_libssh2_config.h)

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/clar.suite
  COMMAND ${PYTHON_EXECUTABLE} generate.py
    -o "${CMAKE_CURRENT_BINARY_DIR}" -f "${CLAR_TESTCASES}"
  DEPENDS ${SRC_CLAR} generate.py
  WORKING_DIRECTORY ${CLAR_PATH})

set_source_files_properties(${CLAR_PATH}/clar.c
  PROPERTIES OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/clar.suite)

add_executable(libssh2_clar ${SRC_CLAR} ${SRC_TEST}
  $<TARGET_OBJECTS:libssh2-object>)

target_compile_definitions(libssh2_clar PRIVATE ${LIBSSH2_DEFINES})
# to find generated header
target_include_directories(libssh2_clar PRIVATE
  "${LIBSSH2_INCLUDES}"
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_BINARY_DIR}/../src/"
  "${CMAKE_CURRENT_BINARY_DIR}")

# FIXME: do we want that?
set_target_properties(libssh2_clar PROPERTIES C_STANDARD 90)
set_target_properties(libssh2_clar PROPERTIES RUNTIME_OUTPUT_DIRECTORY
  ${libssh2_BINARY_DIR})

if(${CMAKE_VERSION} VERSION_LESS 2.8.12)
  # Already handled by a global INCLUDE_DIRECTORY()
else()
  target_include_directories(libssh2_clar PRIVATE ../src PUBLIC ../include)
endif()

target_link_libraries(libssh2_clar ${LIBSSH2_LIBS})

add_test(all   "${libssh2_BINARY_DIR}/libssh2_clar" -v)

if(LINT)
  add_dependencies(libssh2_clar lint)
endif()

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
