
//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "native_info_ffi.h"
#include "openssl/opensslconf.h"


const char * openssl_library_version(size_t *len) {
    *len = sizeof(OPENSSL_FULL_VERSION_STR);
    return OPENSSL_FULL_VERSION_STR;
}

int32_t is_native_available(void) {
    return FFI_TRUE;
}
