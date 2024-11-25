# Copyright (C) Viktor Szakats
# SPDX-License-Identifier: BSD-3-Clause

enable_language(CXX)

add_library(standaloneengine STATIC "standaloneengine.cc")
target_include_directories(standaloneengine PRIVATE
  "${PROJECT_SOURCE_DIR}/include")
set_target_properties(standaloneengine PROPERTIES UNITY_BUILD OFF)

add_executable(ssh2_client_fuzzer "ssh2_client_fuzzer.cc" "testinput.h")
target_include_directories(ssh2_client_fuzzer PRIVATE
  "${PROJECT_SOURCE_DIR}/include")
if(LIB_FUZZING_ENGINE)
  if(LIB_FUZZING_ENGINE STREQUAL "-fsanitize=fuzzer")  # FIXME: compiler-specific
    set_target_properties(ssh2_client_fuzzer PROPERTIES LINK_FLAGS "${LIB_FUZZING_ENGINE}")
  else()
    target_link_libraries(ssh2_client_fuzzer ${LIB_FUZZING_ENGINE})
  endif()
else()
  target_link_libraries(ssh2_client_fuzzer standaloneengine)
endif()
target_link_libraries(ssh2_client_fuzzer ${LIB_STATIC} ${LIBSSH2_LIBS_SOCKET})
set_target_properties(ssh2_client_fuzzer PROPERTIES UNITY_BUILD OFF)
