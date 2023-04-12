include(CheckCCompilerFlag)

option(ENABLE_WERROR "Turn compiler warnings into errors" OFF)
option(PICKY_COMPILER "Enable picky compiler options" ON)

if(ENABLE_WERROR)
  if(MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /WX")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /WX")
  else()  # llvm/clang and gcc style options
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
  endif()
endif()

if(MSVC)
  # Use the highest warning level for Visual Studio.
  if(PICKY_COMPILER)
    if(CMAKE_CXX_FLAGS MATCHES "[/-]W[0-4]")
      string(REGEX REPLACE "[/-]W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    else()
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
    endif()
    if(CMAKE_C_FLAGS MATCHES "[/-]W[0-4]")
      string(REGEX REPLACE "[/-]W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    else()
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
    endif()
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_C_COMPILER_ID MATCHES "Clang")

  # https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html
  # https://clang.llvm.org/docs/DiagnosticsReference.html

  if(NOT CMAKE_CXX_FLAGS MATCHES "-Wall")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
  endif()
  if(NOT CMAKE_C_FLAGS MATCHES "-Wall")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
  endif()

  if(PICKY_COMPILER)

    # Assume these options always exist.
    # Require clang 3.0 / gcc 2.96 or later.
    set(WARNOPTS_ENABLE
      -W
      -pedantic
      -Wconversion                     # clang  3.0  gcc  2.95
      -Wfloat-equal                    # clang  1.0  gcc  2.96
      -Winline                         # clang  1.0  gcc  1.0
      -Wmissing-declarations           # clang  1.0  gcc  2.7
      -Wmissing-prototypes             # clang  1.0  gcc  1.0
      -Wnested-externs                 # clang  1.0  gcc  1.0
      -Wno-format-nonliteral           # clang  1.0  gcc  2.96
      -Wno-long-long                   # clang  1.0  gcc  2.95
      -Wno-multichar                   # clang  1.0  gcc  2.95
      -Wpointer-arith                  # clang  1.0  gcc  1.0
      -Wshadow                         # clang  1.0  gcc  2.95
      -Wsign-compare                   # clang  1.0  gcc  2.95
      -Wundef                          # clang  1.0  gcc  2.95
      -Wunused                         # clang  1.1  gcc  2.95
      -Wwrite-strings                  # clang  1.0  gcc  1.0
    )

    # Enable if available
    set(WARNOPTS_TOCHECK
      -Wdouble-promotion               # clang  3.6  gcc  4.6
      -Wenum-conversion                # clang  3.2  gcc 10.0 (for C, 11.0 for C++)
      -Wunused-const-variable          # clang  3.4  gcc  6.0
    )

    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
      # common with gcc, but skip detection with clang
      list(APPEND WARNOPTS_ENABLE
        -Wcast-align                   # clang  1.0  gcc  4.2
        -Wdeclaration-after-statement  # clang  1.0  gcc  3.4
        -Wempty-body                   # clang  3.0  gcc  4.3
        -Wendif-labels                 # clang  1.0  gcc  3.3
        -Wignored-qualifiers           # clang  3.0  gcc  4.3
        -Wno-sign-conversion           # clang  3.0  gcc  4.3
        -Wno-system-headers            # clang  1.0  gcc  3.0
        -Wstrict-prototypes            # clang  1.0  gcc  3.3
        -Wtype-limits                  # clang  3.0  gcc  4.3
        -Wvla                          # clang  2.8  gcc  4.3
      )
      # clang-only
      list(APPEND WARNOPTS_ENABLE
        -Wshift-sign-overflow          # clang  2.9
        -Wshorten-64-to-32             # clang  1.0
      )
      list(APPEND WARNOPTS_TOCHECK
        -Wassign-enum                  # clang  7.0
        -Wcomma                        # clang  3.9
        -Wextra-semi-stmt              # clang  7.0
      )
    else()
      if(MINGW)
        list(APPEND WARNOPTS_TOCHECK
          -Wno-pedantic-ms-format      #             gcc  4.5 (mingw-only)
        )
      endif()
      # common with clang
      list(APPEND WARNOPTS_TOCHECK
        -Wcast-align                   # clang  1.0  gcc  4.2
        -Wdeclaration-after-statement  # clang  1.0  gcc  3.4
        -Wempty-body                   # clang  3.0  gcc  4.3
        -Wendif-labels                 # clang  1.0  gcc  3.3
        -Wignored-qualifiers           # clang  3.0  gcc  4.3
        -Wno-sign-conversion           # clang  3.0  gcc  4.3
        -Wno-system-headers            # clang  1.0  gcc  3.0
        -Wstrict-prototypes            # clang  1.0  gcc  3.3
        -Wtype-limits                  # clang  3.0  gcc  4.3
        -Wvla                          # clang  2.8  gcc  4.3
      )
      # gcc-only
      list(APPEND WARNOPTS_TOCHECK
        -Walloc-zero                   #             gcc  7.0
        -Warith-conversion             #             gcc 10.0
        -Wduplicated-branches          #             gcc  7.0
        -Wduplicated-cond              #             gcc  6.0
        -Wformat-overflow=2            #             gcc  7.0
        -Wformat-truncation=1          #             gcc  7.0
        -Wformat=2                     # clang  3.0  gcc  4.8 (clang part-default, enabling it fully causes -Wformat-nonliteral warnings)
        -Wmissing-parameter-type       #             gcc  4.3
        -Wold-style-declaration        #             gcc  4.3
        -Wrestrict                     #             gcc  7.0
        -Wshift-negative-value         # clang  3.7  gcc  6.0 (clang default)
        -Wshift-overflow=2             # clang  3.0  gcc  6.0 (clang default: -Wshift-overflow)
        -Wstrict-aliasing=3            #             gcc  4.0
      )

      # Enable based on compiler version
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 5.0)
        list(APPEND WARNOPTS_ENABLE -Warray-bounds=2 -ftree-vrp)
                                       # clang  3.0  gcc  5.0 (clang default: -Warray-bounds)
      endif()
      if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 6.0)
        list(APPEND WARNOPTS_ENABLE -Wnull-dereference -fdelete-null-pointer-checks)
                                       # clang  3.0  gcc  6.0 (clang default)
      endif()
    endif()

    foreach(_CCOPT ${WARNOPTS_ENABLE})
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
    endforeach()

    foreach(_CCOPT ${WARNOPTS_TOCHECK})
      # surprisingly, CHECK_C_COMPILER_FLAG needs a new variable to store each new
      # test result in.
      string(MAKE_C_IDENTIFIER "OPT${_CCOPT}" _optvarname)
      # GCC only warns about unknown -Wno- options if there are also other diagnostic messages,
      # so test for the positive form instead
      string(REPLACE "-Wno-" "-W" _CCOPT_ON "${_CCOPT}")
      check_c_compiler_flag(${_CCOPT_ON} ${_optvarname})
      if(${_optvarname})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
      endif()
    endforeach()
  endif()
endif()
