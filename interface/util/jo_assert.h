
//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

#ifndef HARD_ASSERT_H
#define HARD_ASSERT_H

//
// Based on ossl_assert except prints to stderr only
//

# if defined(__GNUC__) || defined(__clang__)
#  define jo_likely(x)     __builtin_expect(!!(x), 1)
#  define jo_unlikely(x)   __builtin_expect(!!(x), 0)
# else
#  define jo_likely(x)     x
#  define jo_unlikely(x)   x
# endif

// jo_assert always aborts on failure, including under NDEBUG.
#include <stdlib.h>
#include <stdio.h>
static inline void jo_assert_f(int expr, const char *exprstr,
                               const char *file, int line)
{
    if (jo_unlikely(!expr)) {
        fprintf(stderr, "Assertion failed: %s, file %s, line %d\n",
                exprstr, file, line);
        fflush(stderr);
        abort();
    }
}

#define jo_assert(x) jo_assert_f((x) != 0, #x, __FILE__, __LINE__)


#endif //HARD_ASSERT_H
