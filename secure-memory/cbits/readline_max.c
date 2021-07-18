// SPDX-FileCopyrightText: 2021 Serokell <https://serokell.io/>
//
// SPDX-License-Identifier: MPL-2.0

#if defined(mingw32_HOST_OS) /* windows */

// TODO: implement a version for Windows

#else /* not windows => unix */

#include <unistd.h>

// Read a newline-terminated string into `buf` from stdin.
//
// The size of `buf` must be at least `max_len`.
// If the user enters more than `max_len` characters before
// ending the line, the extra characters will be silently discarded.
//
// Returns the actual length of the string that was read or a negative
// number if an error happened in the process.
int readline_max(int max_len, void *buf) {
  const int fin = STDIN_FILENO;
  char *p = (char*)buf;
  int length = 0;

  int res = -1;
  char c;
  while (res = read(fin, &c, 1) == 1) {
    if (c == '\n' || c == '\r') {
        break;
    } else {
      if (length < max_len) {
        *p = c;
        p += 1;
        length += 1;
      } else {
        // discard the remainder
      }
    }
  }

  if (res < 0) {
    return res;
  } else {
    return length;
  }
}

#endif
