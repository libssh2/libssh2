#!/usr/bin/env bash

set -e

if [ -n "$SKIP_TESTS" ]; then
    exit 0
fi

SOURCE_DIR=${SOURCE_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && dirname $( pwd ) )}

. $SOURCE_DIR/ci/conf.sh

TMPDIR=${TMPDIR:-/tmp}
USER=${USER:-$(whoami)}

SUCCESS=1

if [ ! -d "$BUILD_DIR" ]; then
    echo "No buildir"
    exit -1
fi

cd "$BUILD_DIR"

cleanup() {
    echo "Cleaning up..."
    echo "Done."
}

failure() {
    echo "Test exited with code: $1"
    SUCCESS=0
}

VALGRIND="valgrind --leak-check=full --show-reachable=yes --track-origins=yes --error-exitcode=125 --num-callers=50 --suppressions=\"$SOURCE_DIR/libssh2_clar.supp\""
LEAKS="MallocStackLogging=1 MallocScribble=1 MallocLogFile=/dev/null CLAR_AT_EXIT=\"leaks -quiet \$PPID\""

# Ask ctest what it would run if we were to invoke it directly.  This lets
# us manage the test configuration in a single place (tests/CMakeLists.txt)
# instead of running clar here as well.  But it allows us to wrap our test
# harness with a leak checker like valgrind.  Append the option to write
# JUnit-style XML files.
run_test() {
    TEST_CMD=$(ctest -N -V -R "^${1}$" | sed -n 's/^[0-9]*: Test command: //p')

    if [ -z "$TEST_CMD" ]; then
        echo "Could not find tests: $1"
        exit 1
    fi

    TEST_CMD="${TEST_CMD} -r${BUILD_DIR}/results_${1}.xml"

    if [ "$LEAK_CHECK" = "valgrind" ]; then
        RUNNER="$VALGRIND $TEST_CMD"
    elif [ "$LEAK_CHECK" = "leaks" ]; then
        RUNNER="$LEAKS $TEST_CMD"
    else
        RUNNER="$TEST_CMD"
    fi

    eval $RUNNER || failure
}

# Run the tests that do not require network connectivity.

if [ -z "$SKIP_OFFLINE_TESTS" ]; then
    echo ""
    echo "##############################################################################"
    echo "## Running (all) tests"
    echo "##############################################################################"

    run_test all
fi

cleanup

if [ "$SUCCESS" -ne "1" ]; then
    echo "Some tests failed."
    exit 1
fi

echo "Success."
exit 0
