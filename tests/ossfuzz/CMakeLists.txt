# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

enable_language(CXX)

add_library(standaloneengine STATIC "standaloneengine.cc")
target_include_directories(standaloneengine PRIVATE
  "${PROJECT_SOURCE_DIR}/include")
set_target_properties(standaloneengine PROPERTIES UNITY_BUILD OFF)

foreach(_fuzz_target IN ITEMS
  ssh2_client_fuzzer
  ssh2_sftp_packet_fuzzer
  ssh2_knownhost_fuzzer)

  add_executable(${_fuzz_target} "${_fuzz_target}.cc" "testinput.h")
  target_include_directories(${_fuzz_target} PRIVATE
    "${PROJECT_SOURCE_DIR}/include")
  if(LIB_FUZZING_ENGINE)
    if(LIB_FUZZING_ENGINE STREQUAL "-fsanitize=fuzzer")  # FIXME: compiler-specific
      set_property(TARGET ${_fuzz_target} APPEND PROPERTY LINK_OPTIONS "${LIB_FUZZING_ENGINE}")
    else()
      target_link_libraries(${_fuzz_target} ${LIB_FUZZING_ENGINE})
    endif()
  else()
    target_link_libraries(${_fuzz_target} standaloneengine)
  endif()
  target_link_libraries(${_fuzz_target} ${LIB_STATIC} ${LIBSSH2_LIBS_SOCKET})
  set_target_properties(${_fuzz_target} PROPERTIES UNITY_BUILD OFF)
endforeach()
