//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef RAND_H
#define RAND_H

#include <stdint.h>

int32_t rand_init(const char *provider_name, int32_t *created);

void rand_destroy(void);

int32_t rand_random_bytes(uint8_t *output, int32_t output_len, int32_t strength);

#endif //RAND_H
