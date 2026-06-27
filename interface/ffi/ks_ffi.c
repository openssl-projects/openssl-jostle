//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "types.h"

#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>

#include "../util/jo_assert.h"
#include "../util/ks.h"

ks_ctx *JoKS_Allocate(const char *type, int32_t *err) {
    if (err == NULL) {
        return NULL;
    }
    if (type == NULL) {
        *err = JO_KS_TYPE_IS_NULL;
        return NULL;
    }

    return ks_allocate(type, err);
}

void JoKS_Dispose(ks_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    ks_free(ctx);
}

int32_t JoKS_Load(ks_ctx *ctx, uint8_t *input, size_t input_size, uint8_t *password, size_t password_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (input == NULL && input_size != 0) {
        return JO_FAILED_ACCESS_INPUT;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }

    return ks_load(ctx, input, input_size, password, password_size);
}

int32_t JoKS_StoreLen(ks_ctx *ctx, uint8_t *password, size_t password_size,
                      int32_t key_pbe, int32_t cert_pbe, int32_t mac_scheme,
                      int32_t mac_digest, int32_t pbe_iter, int32_t mac_iter,
                      int32_t *err) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    if (err == NULL) {
        return 0;
    }
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (password == NULL && password_size != 0) {
        *err = JO_FAILED_ACCESS_KEY;
        return 0;
    }
    if (pbe_iter < 0) {
        *err = JO_KS_PBE_ITER_NEGATIVE;
        return 0;
    }
    if (mac_iter < 0) {
        *err = JO_KS_MAC_ITER_NEGATIVE;
        return 0;
    }

    *err = ks_store(ctx, &out, &out_len, password, password_size,
            key_pbe, cert_pbe, mac_scheme, mac_digest, pbe_iter, mac_iter);
    if (UNSUCCESSFUL(*err)) {
        goto exit;
    }
    if (out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }
    result = (int32_t) out_len;

exit:
    OPENSSL_clear_free(out, out_len);
    return result;
}

int32_t JoKS_Store(ks_ctx *ctx, uint8_t *password, size_t password_size,
                   int32_t key_pbe, int32_t cert_pbe, int32_t mac_scheme,
                   int32_t mac_digest, int32_t pbe_iter, int32_t mac_iter,
                   uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (pbe_iter < 0) {
        return JO_KS_PBE_ITER_NEGATIVE;
    }
    if (mac_iter < 0) {
        return JO_KS_MAC_ITER_NEGATIVE;
    }

    ret = ks_store(ctx, &out, &out_len, password, password_size,
            key_pbe, cert_pbe, mac_scheme, mac_digest, pbe_iter, mac_iter);
    if (UNSUCCESSFUL(ret) || out == NULL) {
        goto exit;
    }
    if (output_size < out_len) {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    memcpy(output, out, out_len);
    ret = JO_SUCCESS;

exit:
    OPENSSL_clear_free(out, out_len);
    return ret;
}

int32_t JoKS_GetKeyLen(ks_ctx *ctx, const char *alias, uint8_t *password, size_t password_size, int32_t *err) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    if (err == NULL) {
        return 0;
    }
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }
    if (password == NULL && password_size != 0) {
        *err = JO_FAILED_ACCESS_KEY;
        return 0;
    }

    *err = ks_get_key(ctx, alias, &out, &out_len, password, password_size);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }
    if (out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }
    result = (int32_t) out_len;

exit:
    OPENSSL_clear_free(out, out_len);
    return result;
}

int32_t JoKS_GetKey(ks_ctx *ctx, const char *alias, uint8_t *password, size_t password_size,
                    uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    ret = ks_get_key(ctx, alias, &out, &out_len, password, password_size);
    if (UNSUCCESSFUL(ret) || out == NULL) {
        goto exit;
    }
    if (output_size < out_len) {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    memcpy(output, out, out_len);
    ret = JO_SUCCESS;

exit:
    OPENSSL_clear_free(out, out_len);
    return ret;
}

int32_t JoKS_GetCertificateChainLen(ks_ctx *ctx, const char *alias, int32_t *err) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    if (err == NULL) {
        return 0;
    }
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }

    *err = ks_get_certificate_chain(ctx, alias, &out, &out_len);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }
    if (out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }
    result = (int32_t) out_len;

exit:
    OPENSSL_clear_free(out, out_len);
    return result;
}

int32_t JoKS_GetCertificateChain(ks_ctx *ctx, const char *alias, uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    ret = ks_get_certificate_chain(ctx, alias, &out, &out_len);
    if (UNSUCCESSFUL(ret) || out == NULL) {
        goto exit;
    }
    if (output_size < out_len) {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    memcpy(output, out, out_len);
    ret = JO_SUCCESS;

exit:
    OPENSSL_clear_free(out, out_len);
    return ret;
}

int32_t JoKS_SetKey(ks_ctx *ctx, const char *alias, uint8_t *key, size_t key_size,
                    uint8_t *password, size_t password_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (key == NULL) {
        return JO_KS_KEY_IS_NULL;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }

    return ks_set_key(ctx, alias, key, key_size, password, password_size);
}

int32_t JoKS_SetCertificateChain(ks_ctx *ctx, const char *alias, uint8_t *chain, size_t chain_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (chain == NULL && chain_size != 0) {
        return JO_FAILED_ACCESS_INPUT;
    }

    return ks_set_certificate_chain(ctx, alias, chain, chain_size);
}

int32_t JoKS_SetCertificateEntry(ks_ctx *ctx, const char *alias, uint8_t *certificate, size_t certificate_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (certificate == NULL && certificate_size != 0) {
        return JO_FAILED_ACCESS_INPUT;
    }

    return ks_set_certificate_entry(ctx, alias, certificate, certificate_size);
}

int32_t JoKS_DeleteEntry(ks_ctx *ctx, const char *alias) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    return ks_delete_entry(ctx, alias);
}

int32_t JoKS_GetAliasesLen(ks_ctx *ctx, int32_t *err) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    if (err == NULL) {
        return 0;
    }
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }

    *err = ks_get_aliases(ctx, &out, &out_len);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }
    if (out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }
    result = (int32_t) out_len;

exit:
    OPENSSL_clear_free(out, out_len);
    return result;
}

int32_t JoKS_GetAliases(ks_ctx *ctx, uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    ret = ks_get_aliases(ctx, &out, &out_len);
    if (UNSUCCESSFUL(ret) || out == NULL) {
        goto exit;
    }
    if (output_size < out_len) {
        ret = JO_OUTPUT_TOO_SMALL;
        goto exit;
    }

    memcpy(output, out, out_len);
    ret = JO_SUCCESS;

exit:
    OPENSSL_clear_free(out, out_len);
    return ret;
}

int32_t JoKS_ContainsAlias(ks_ctx *ctx, const char *alias) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    return ks_contains_alias(ctx, alias);
}

int32_t JoKS_Size(ks_ctx *ctx) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    return ks_size(ctx);
}

int32_t JoKS_IsKeyEntry(ks_ctx *ctx, const char *alias) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    return ks_is_key_entry(ctx, alias);
}

int32_t JoKS_IsCertificateEntry(ks_ctx *ctx, const char *alias) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }

    return ks_is_certificate_entry(ctx, alias);
}

int64_t JoKS_GetCreationDate(ks_ctx *ctx, const char *alias, int32_t *err) {
    if (err == NULL) {
        return 0;
    }
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }

    return ks_get_creation_date(ctx, alias, err);
}
