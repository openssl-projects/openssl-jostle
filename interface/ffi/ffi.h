//  Copyright 2005-2025 The OpenSSL Project Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://www.openssl.org/source/license.html

#ifndef FFI_H
#define FFI_H
#include <stdbool.h>

#include "types.h"

/*
* Calls free on the passed in pointer.
* Use this in cases where security is not relevant, otherwise
* use the appropriate free for whatever you are doing.
*/
void ffi_free_unsecure_null_safe(void *ptr);




#endif //FFI_H
