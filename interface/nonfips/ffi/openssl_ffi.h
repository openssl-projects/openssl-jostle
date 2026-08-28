//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE



#ifndef OPENSSL_FFI_H
#define OPENSSL_FFI_H

#include <stdint.h>
#include "types.h"


/*
* set the openssl module
*/
int32_t JoOpenSSL_setModule(const char *prov_name);

/*
* return any available openssl errors
*/
char *JoOpenSSL_getErrors(uint64_t *len);

/*
* Can this library's lib ctx resolve name for op_type? Returns 1/0, or
* JO_NAME_IS_NULL / JO_UNEXPECTED_STATE for an unusable argument. Backs the
* base provider's registration gates - see util/capability.h.
*/
int32_t JoOpenSSL_canFetch(int32_t op_type, const char *name);


#endif //OPENSSL_FFI_H
