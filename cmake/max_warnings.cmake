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

# clang missing:
# -Wassign-enum
# -Wcomma
# -Wextra-semi-stmt
# -Wshift-sign-overflow
# -Wshorten-64-to-32

# gcc missing:
# -Walloc-zero
# -Warray-bounds=2 -ftree-vrp
# -Wduplicated-branches
# -Wduplicated-cond
# -Wformat-overflow=2
# -Wformat-truncation=2
# -Wformat=2
# -Wnull-dereference -fdelete-null-pointer-checks
# -Wrestrict
# -Wshift-negative-value
# -Wshift-overflow=2
# -Wunused-const-variable

  if(PICKY_COMPILER)
    message(STATUS "C compiler version: ${CMAKE_C_COMPILER_VERSION}")
    foreach(_CCOPT -pedantic -W
        -Warith-conversion                   # gcc
        -Wcast-align
        -Wclobbered                          # gcc, part of -Wextra
        -Wconversion
        -Wdeclaration-after-statement
        -Wdouble-promotion
        -Wempty-body
        -Wendif-labels
        -Wenum-conversion
        -Wfloat-equal
        -Wignored-qualifiers
        -Winline
        -Wmissing-declarations
        -Wmissing-parameter-type             # gcc
        -Wmissing-prototypes
        -Wnested-externs
        -Wold-style-declaration              # gcc
        -Wpointer-arith
        -Wshadow
        -Wsign-compare
        -Wstrict-aliasing=3                  # gcc
        -Wstrict-prototypes
        -Wtype-limits
        -Wundef
        -Wunused
        -Wvla
        -Wwrite-strings
      )
      # surprisingly, CHECK_C_COMPILER_FLAG needs a new variable to store each new
      # test result in.
      string(MAKE_C_IDENTIFIER "OPT${_CCOPT}" _optvarname)
      check_c_compiler_flag(${_CCOPT} ${_optvarname})
      if(${_optvarname})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_CCOPT}")
      endif()
    endforeach()
    foreach(_CCOPT
        format-nonliteral
        long-long
        multichar
        pedantic-ms-format                   # gcc
        sign-conversion
        system-headers
      )
      # GCC only warns about unknown -Wno- options if there are also other diagnostic messages,
      # so test for the positive form instead
      string(MAKE_C_IDENTIFIER "OPT${_CCOPT}" _optvarname)
      check_c_compiler_flag("-W${_CCOPT}" ${_optvarname})
      if(${_optvarname})
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-${_CCOPT}")
      endif()
    endforeach()
  endif()
endif()
