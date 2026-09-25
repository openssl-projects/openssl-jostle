//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#ifndef RAND_UPCALL_FFM_H
#define RAND_UPCALL_FFM_H
#include <stdint.h>
#include <stdlib.h>

typedef int32_t (*ffm_get_rand)(uint8_t *, size_t, int32_t, int32_t);

#endif //RAND_UPCALL_FFM_H
