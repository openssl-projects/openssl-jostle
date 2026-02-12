//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE



#ifndef MD_H
#define MD_H

#include <openssl/params.h>
#include <openssl/types.h>

    typedef struct md_ctx {
        EVP_MD_CTX *mdctx;
        const EVP_MD *md_type;
        int32_t digest_byte_length;
        int xof;
    } md_ctx;

    md_ctx * md_ctx_create(const char*name, int xof_len, int *err);
    void md_ctx_destroy(md_ctx *ctx);
    int32_t md_ctx_update(md_ctx *ctx, uint8_t *data, size_t len);
    int32_t md_ctx_finalize(md_ctx *ctx, uint8_t *digest);
    int32_t md_ctx_reset(md_ctx *ctx);


#endif //MD_H
