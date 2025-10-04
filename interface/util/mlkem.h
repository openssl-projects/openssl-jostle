

//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef MLKEM_H
#define MLKEM_H
#include <stdint.h>
#include "key_spec.h"

#define MLKEM_SEED_LEN 64

int32_t mlkem_generate_key_pair(key_spec *key_pair, int32_t type, uint8_t *seed, size_t seed_len);

int32_t mlkem_get_public_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t mlkem_get_private_encoded(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t mlkem_get_private_seed(key_spec *key_spec, uint8_t *out, size_t out_len);

int32_t mlkem_decode_private_key(key_spec *key_spec, int32_t typeId,  uint8_t *src, size_t src_len);

int32_t mlkem_decode_public_key(key_spec *key_spec,  int32_t typeId,   uint8_t *src, size_t src_len);

#endif //MLKEM_H
