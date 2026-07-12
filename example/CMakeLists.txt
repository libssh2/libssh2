# Copyright (C) Alexander Lamaison <alexander.lamaison@gmail.com>
# Copyright (C) Viktor Szakats
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# SPDX-License-Identifier: BSD-3-Clause

list(APPEND LIBSSH2_LIBS ${LIBSSH2_LIBS_SOCKET})

libssh2_transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
# Get noinst_PROGRAMS variable
include("${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")

add_custom_target(libssh2-examples)

set(_all_src "")
set(_all_canary "")
set(_all "all")
foreach(_target IN LISTS noinst_PROGRAMS _all)  # keep '_all' last
  if(_target STREQUAL "all")
    set(_target "libssh2-example-${_all}")
    add_library(${_target} OBJECT EXCLUDE_FROM_ALL ${_all_src})
    if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")  # MSVC but exclude clang-cl
      # CMake generates a static library for the OBJECT target. Silence these 'lib.exe' warnings:
      # warning LNK4006: main already defined in ....obj; second definition ignored
      # warning LNK4221: This object file does not define any previously undefined public symbols,
      #                  [...] not be used by any link operation that consumes this library
      set_target_properties(${_target} PROPERTIES STATIC_LIBRARY_OPTIONS "-ignore:4006;-ignore:4221")
    endif()
    add_custom_target(libssh2-examples-build)  # Special target to compile all tests quickly and build a single test to probe linkage
    add_dependencies(libssh2-examples-build ${_target} ${_all_canary})  # Include a full build of a single test
  else()
    set(_all_canary ${_target})  # Save the last test for the libssh2-examples-build target
    list(APPEND _all_src "${_target}.c")
    add_executable(${_target} EXCLUDE_FROM_ALL "${_target}.c")
    add_dependencies(libssh2-examples ${_target})
  endif()
  target_include_directories(${_target} PRIVATE
    "${PROJECT_BINARY_DIR}/src"
    "${PROJECT_SOURCE_DIR}/src")
  target_link_libraries(${_target} ${LIB_SELECTED} ${LIBSSH2_LIBS})
  set_property(TARGET ${_target} APPEND PROPERTY COMPILE_OPTIONS "${LIBSSH2_PICKY_C_FLAGS}")
  set_target_properties(${_target} PROPERTIES UNITY_BUILD OFF)
endforeach()
