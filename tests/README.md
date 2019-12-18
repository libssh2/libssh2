# libssh2 Testing Quickstart

The libssh2 project uses [Clar](https://github.com/clar-test/clar) as its test harness, with some
additional changes for containerization purposes. The test suite files live in `tests/testcases`,
fixtures can be used from `resources`, most of the "constant/data" things is provided as
\#defines in `clar_libssh2.h`.

You'll need to have built libssh2 with the testsuite enabled (`-DBUILD_TESTING=1`, on by default),
to generate the `libssh2_clar` test executable. From your CMake build root, you should
find a fully working version at `./tests/libssh2_clar`.

## Basic usage

- `-v` enables verbose output
- `-s` focuses the specific test (eg, `-sagent`, `-sagent:slow:timeouts`)
- `-x` disables the test

## Writing tests

You can use the following blank template to create a new test suite, or add a new function with
the "correct shape" to an exisiting one. Clar uses a regex to pick test functions out — `initialize` and `cleanup` are reserved for practical reasons, the rest will show up as the test name.

```c
#include "clar_libssh2.h"

void test_blank__initialize(void)
{
}

void test_blank__cleanup(void)
{
}

void test_blank__basic(void)
{
}
```

See the clar headers for the available assertion helpers (search for `cl_assert`), but we provide quite a few specific ones on top of this in `clar_libssh2.h`.
