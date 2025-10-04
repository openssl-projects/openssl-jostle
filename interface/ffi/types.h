//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef TYPES_H
#define TYPES_H

#include <stddef.h>
#include <stdbool.h>

#include "../util/bc_err_codes.h"


#define FFI_BOOL int32_t
#define FFI_TRUE 1
#define FFI_FALSE 0

inline bool check_in_range(size_t size, size_t offset, size_t len) {
    return (len <= size) && (offset <= size - len);
}


#endif //TYPES_H
