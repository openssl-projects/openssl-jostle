//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "ffi.h"

#include <stddef.h>
#include <stdlib.h>

void ffi_free_unsecure_null_safe(void *ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}


