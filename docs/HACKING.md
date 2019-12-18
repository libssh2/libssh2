# libssh2 code guidelines

The guidelines are enforced via `./ci/checksrc.pl`. A helper script with the correct rules is available as `./ci/checksrc.sh`.

CMake has a `-DLINT=ON` options that will run the checker as part of a build, and show up as build errors if your IDE supports it.
