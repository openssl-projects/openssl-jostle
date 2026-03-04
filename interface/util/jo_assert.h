
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

# ifdef NDEBUG
#  define jo_assert(x) jo_likely((x) != 0)
# else
#include <printf.h>
#include <stdlib.h>
static inline  void jo_assert_f(int expr, const char *exprstr,
                                              const char *file, int line)
{
    if (!expr) {
        fprintf(stderr,exprstr,file,line);
        fflush(stderr);
        abort();
    }

}

#  define jo_assert(x) jo_assert_f((x) != 0, "Assertion failed: "#x, \
__FILE__, __LINE__)

# endif


#endif //HARD_ASSERT_H
