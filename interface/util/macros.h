//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef JOSTLE_UTIL_MACROS_H
#define JOSTLE_UTIL_MACROS_H

// Suppress unused-parameter warnings on gcc/clang/MSVC. In the util tier so
// shared code can use it without reaching into bridge-specific headers.
#define UNUSED(x) (void)(x) /*  Prefer to keep the warnings. */

#endif // JOSTLE_UTIL_MACROS_H
