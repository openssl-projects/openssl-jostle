//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef ENCAPDECAP_H
#define ENCAPDECAP_H

#include <stdint.h>

#include "key_spec.h"


int32_t encap(const key_spec *key_spec, const char *kem, uint8_t *secret, size_t secret_len, uint8_t *out,
               size_t out_len);

int32_t decap(const key_spec *key_spec, const char *kem, const uint8_t *input, size_t in_len, uint8_t *out,
               size_t out_len);


#endif //ENCAPDECAP_H
