
//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef NATIVE_INFO_FFI_H
#define NATIVE_INFO_FFI_H

#include <stdint.h>
#include "types.h"

const char * openssl_library_version(size_t *len);

FFI_BOOL is_native_available(void);

#endif //NATIVE_INFO_FFI_H
