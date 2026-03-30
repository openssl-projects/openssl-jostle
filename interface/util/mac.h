//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef JOSTLE_MAC_H
#define JOSTLE_MAC_H

#include <stddef.h>
#include <stdint.h>

typedef struct jo_mac_ctx_st jo_mac_ctx;

int32_t jo_mac_new(const char *mac_name, const char *canonical_name, uintptr_t *out_ctx);
int32_t jo_mac_init(uintptr_t ctx, const uint8_t *key, size_t key_len);
int32_t jo_mac_update(uintptr_t ctx, const uint8_t *in, int32_t off, int32_t len);
int32_t jo_mac_final(uintptr_t ctx, uint8_t *out, int32_t off, int32_t out_len);
int32_t jo_mac_len(uintptr_t ctx);
void jo_mac_reset(uintptr_t ctx);
void jo_mac_free(uintptr_t ctx);
int32_t jo_mac_copy(uintptr_t ctx, uintptr_t *out_ctx);

#endif
