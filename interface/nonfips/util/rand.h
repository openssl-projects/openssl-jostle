//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef RAND_H
#define RAND_H

#include <stddef.h>
#include <stdint.h>

typedef struct jo_rand_ctx_st JO_RAND_CTX;

#define JO_RAND_MAX_STRENGTH ((int32_t) 256)

int32_t rand_init(const char *provider_name, int32_t *created);

/**
 * FIPS variant of rand_init: create the SecureRandom-backing lib ctx with
 * the OpenSSL FIPS module + base provider (jostle_fips_configure_libctx),
 * so every SecureRandom DRBG chains to the module's own primary DRBG. Same
 * one-shot first-name-wins contract as rand_init.
 */
int32_t rand_init_fips(const char *module_dir, const char *prov_name,
                       const char *config_path, int32_t *created);

void rand_destroy(void);

JO_RAND_CTX *rand_ctx_create(const char *mechanism, const char *variant, int use_df,
                             int32_t strength, int prediction_resistant,
                             const uint8_t *personalization_string,
                             size_t personalization_string_len,
                             int32_t *err);

void rand_ctx_destroy(JO_RAND_CTX *ctx);

int32_t rand_ctx_random_bytes(JO_RAND_CTX *ctx, uint8_t *output,
                              int32_t output_len, int32_t strength,
                              int prediction_resistant,
                              const uint8_t *additional_input,
                              size_t additional_input_len);

int32_t rand_ctx_reseed(JO_RAND_CTX *ctx, int32_t strength,
                        int prediction_resistant,
                        const uint8_t *additional_input,
                        size_t additional_input_len);

int32_t rand_drbg_strength(const char *mechanism, const char *variant);

#endif //RAND_H
