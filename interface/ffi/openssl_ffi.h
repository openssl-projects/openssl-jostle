//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

//
// Created by MEGAN WOODS on 16/3/2025.
//

#ifndef OPENSSL_FFI_H
#define OPENSSL_FFI_H

#include <stdint.h>
#include "types.h"


/*
* set the openssl module
*/
int32_t set_openssl_module(const char *prov_name);

/*
* return any available openssl errors
*/
char *get_ossl_errors(uint64_t *len);


#endif //OPENSSL_FFI_H
