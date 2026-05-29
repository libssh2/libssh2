<!--
Copyright (C) The libssh2 project and its contributors.

SPDX-License-Identifier: BSD-3-Clause
-->

# libssh2 source code style guide

- 4 level indent
- spaces-only (no tabs)
- open braces on the if/for line:

  ```c
  if(banana) {
      go_nuts();
  }
  ```

- keep source lines shorter than 80 columns
- See `libssh2-style.el` for how to achieve this within Emacs
