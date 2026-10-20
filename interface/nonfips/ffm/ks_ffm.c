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

/*
 * len is the string's UTF-8 byte count from Java. An embedded NUL makes strlen
 * shorter, and the C string would silently end there: refuse it, as the JNI
 * bridge refuses the modified-UTF-8 C0 80 pair.
 */
static int has_nul(const char *s, size_t len) {
    return strnlen(s, len) != len;
}

ks_ctx *JoKS_Allocate(const char *type, size_t type_len, int32_t *err, int32_t err_len) {
    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (type == NULL) {
        *err = JO_KS_TYPE_IS_NULL;
        return NULL;
    }
    /* type_len is the UTF-8 byte count: a type with an embedded NUL names nothing we serve, as on JNI. */
    if (strnlen(type, type_len) != type_len) {
        *err = JO_KS_TYPE_UNSUPPORTED;
        return NULL;
    }

    return ks_allocate(type, err);
}

void JoKS_Dispose(ks_ctx *ctx) {
    /* The handle is the SPI's own reference, so a wrong kind is a jostle fault: abort, never free in silence. */
    int32_t rc = ks_free(ctx);
    jo_assert(rc == JO_SUCCESS);
}

int32_t JoKS_Load(ks_ctx *ctx, uint8_t *input, size_t input_size, uint8_t *password, size_t password_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
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
                      int32_t secret_form, void *rnd_src, int32_t *err, int32_t err_len) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        *err = JO_KS_CTX_WRONG_KIND;
        return 0;
    }
    if (password == NULL && password_size != 0) {
        *err = JO_FAILED_ACCESS_KEY;
        return 0;
    }
    if (pbe_iter < 1) {
        *err = JO_KS_PBE_ITER_NEGATIVE;
        return 0;
    }
    if (mac_iter < 1) {
        *err = JO_KS_MAC_ITER_NEGATIVE;
        return 0;
    }
    if (rnd_src == NULL) {
        *err = JO_RAND_NO_RAND_UP_CALL;
        return 0;
    }

    *err = ks_store(ctx, &out, &out_len, password, password_size,
            key_pbe, cert_pbe, mac_scheme, mac_digest, pbe_iter, mac_iter,
            secret_form, rnd_src);
    if (UNSUCCESSFUL(*err)) {
        goto exit;
    }
    if (out_len > INT32_MAX) {
        *err = JO_OUTPUT_TOO_LONG_INT32;
        goto exit;
    }
    /*
     * Cache the built DER so the paired JoKS_Store returns exactly these bytes
     * without rebuilding. A second ks_store would draw Java entropy again and
     * emit an independently-salted keystore -- correctness must not depend on
     * two builds yielding the same length.
     */
    OPENSSL_clear_free(ctx->pending_store, ctx->pending_store_len);
    ctx->pending_store = out;
    ctx->pending_store_len = out_len;
    out = NULL;
    result = (int32_t) out_len;

exit:
    OPENSSL_clear_free(out, out_len);
    return result;
}

int32_t JoKS_Store(ks_ctx *ctx, uint8_t *password, size_t password_size,
                   int32_t key_pbe, int32_t cert_pbe, int32_t mac_scheme,
                   int32_t mac_digest, int32_t pbe_iter, int32_t mac_iter,
                   int32_t secret_form, void *rnd_src, uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (pbe_iter < 1) {
        return JO_KS_PBE_ITER_NEGATIVE;
    }
    if (mac_iter < 1) {
        return JO_KS_MAC_ITER_NEGATIVE;
    }
    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    /*
     * Single-build fast path: return the DER cached by the preceding
     * JoKS_StoreLen instead of rebuilding (no second entropy draw, and the
     * returned bytes are exactly the ones whose length was measured).
     */
    if (ctx->pending_store != NULL) {
        if (output_size < ctx->pending_store_len) {
            ret = JO_OUTPUT_TOO_SMALL;
        } else {
            memcpy(output, ctx->pending_store, ctx->pending_store_len);
            ret = JO_SUCCESS;
        }
        OPENSSL_clear_free(ctx->pending_store, ctx->pending_store_len);
        ctx->pending_store = NULL;
        ctx->pending_store_len = 0;
        return ret;
    }

    ret = ks_store(ctx, &out, &out_len, password, password_size,
            key_pbe, cert_pbe, mac_scheme, mac_digest, pbe_iter, mac_iter,
            secret_form, rnd_src);
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

int32_t JoKS_GetKeyLen(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *password, size_t password_size,
                       int32_t *err, int32_t err_len) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        *err = JO_KS_CTX_WRONG_KIND;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }
    if (has_nul(alias, alias_len)) {
        *err = JO_KS_NAME_HAS_NUL;
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

int32_t JoKS_GetKey(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *password, size_t password_size,
                    uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
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

int32_t JoKS_GetCertificateChainLen(ks_ctx *ctx, const char *alias, size_t alias_len, int32_t *err, int32_t err_len) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        *err = JO_KS_CTX_WRONG_KIND;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }
    if (has_nul(alias, alias_len)) {
        *err = JO_KS_NAME_HAS_NUL;
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

int32_t JoKS_GetCertificateChain(ks_ctx *ctx, const char *alias, size_t alias_len,
                                 uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
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

int32_t JoKS_SetKey(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *key, size_t key_size,
                    uint8_t *password, size_t password_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }
    if (key == NULL) {
        return JO_KS_KEY_IS_NULL;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }

    return ks_set_key(ctx, alias, key, key_size, password, password_size);
}

int32_t JoKS_SetSecret(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *key, size_t key_size,
                       const char *rfc_oid, size_t rfc_oid_len,
                       const char *sun_oid, size_t sun_oid_len,
                       uint8_t *password, size_t password_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (key == NULL) {
        return JO_KS_KEY_IS_NULL;
    }
    if (rfc_oid == NULL || sun_oid == NULL) {
        return JO_KS_SECRET_OID_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }
    if (key_size == 0) {
        return JO_KS_SECRET_EMPTY;
    }
    if (key_size > KS_SECRET_MAX_LEN) {
        return JO_KS_SECRET_TOO_LONG;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }

    if (has_nul(rfc_oid, rfc_oid_len) || has_nul(sun_oid, sun_oid_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_set_secret(ctx, alias, key, key_size, rfc_oid, sun_oid, password, password_size);
}

int32_t JoKS_SetSecretOids(ks_ctx *ctx, const char *alias, size_t alias_len, const char *rfc_oid,
                           size_t rfc_oid_len, const char *sun_oid, size_t sun_oid_len) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (rfc_oid == NULL || sun_oid == NULL) {
        return JO_KS_SECRET_OID_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    if (has_nul(rfc_oid, rfc_oid_len) || has_nul(sun_oid, sun_oid_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_set_secret_oids(ctx, alias, rfc_oid, sun_oid);
}

int32_t JoKS_GetSecretLen(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *password, size_t password_size,
                          int32_t *err, int32_t err_len) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        *err = JO_KS_CTX_WRONG_KIND;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }
    if (has_nul(alias, alias_len)) {
        *err = JO_KS_NAME_HAS_NUL;
        return 0;
    }
    if (password == NULL && password_size != 0) {
        *err = JO_FAILED_ACCESS_KEY;
        return 0;
    }

    *err = ks_get_secret(ctx, alias, &out, &out_len, password, password_size);
    if (UNSUCCESSFUL(*err) || out == NULL) {
        goto exit;
    }
    /* Bounded by KS_SECRET_MAX_LEN plus the OID and DER headers. */
    jo_assert(out_len <= KS_SECRET_MAX_LEN + 256);
    result = (int32_t) out_len;

exit:
    OPENSSL_clear_free(out, out_len);
    return result;
}

int32_t JoKS_GetSecret(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *password, size_t password_size,
                       uint8_t *output, size_t output_size) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t ret;

    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }

    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }
    if (password == NULL && password_size != 0) {
        return JO_FAILED_ACCESS_KEY;
    }
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    ret = ks_get_secret(ctx, alias, &out, &out_len, password, password_size);
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

int32_t JoKS_IsSecretEntry(ks_ctx *ctx, const char *alias, size_t alias_len) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_is_secret_entry(ctx, alias);
}

int32_t JoKS_SetCertificateChain(ks_ctx *ctx, const char *alias, size_t alias_len, uint8_t *chain, size_t chain_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }
    if (chain == NULL && chain_size != 0) {
        return JO_FAILED_ACCESS_INPUT;
    }

    return ks_set_certificate_chain(ctx, alias, chain, chain_size);
}

int32_t JoKS_SetCertificateEntry(ks_ctx *ctx, const char *alias, size_t alias_len,
                                 uint8_t *certificate, size_t certificate_size) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }
    if (certificate == NULL && certificate_size != 0) {
        return JO_FAILED_ACCESS_INPUT;
    }

    return ks_set_certificate_entry(ctx, alias, certificate, certificate_size);
}

int32_t JoKS_DeleteEntry(ks_ctx *ctx, const char *alias, size_t alias_len) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_delete_entry(ctx, alias);
}

int32_t JoKS_GetAliasesLen(ks_ctx *ctx, int32_t *err, int32_t err_len) {
    uint8_t *out = NULL;
    size_t out_len = 0;
    int32_t result = 0;

    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        *err = JO_KS_CTX_WRONG_KIND;
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

    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
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

int32_t JoKS_ContainsAlias(ks_ctx *ctx, const char *alias, size_t alias_len) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_contains_alias(ctx, alias);
}

int32_t JoKS_Size(ks_ctx *ctx) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }

    return ks_size(ctx);
}

int32_t JoKS_IsKeyEntry(ks_ctx *ctx, const char *alias, size_t alias_len) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_is_key_entry(ctx, alias);
}

int32_t JoKS_IsCertificateEntry(ks_ctx *ctx, const char *alias, size_t alias_len) {
    if (ctx == NULL) {
        return JO_KS_CTX_IS_NULL;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        return JO_KS_CTX_WRONG_KIND;
    }
    if (alias == NULL) {
        return JO_KS_ALIAS_IS_NULL;
    }
    if (has_nul(alias, alias_len)) {
        return JO_KS_NAME_HAS_NUL;
    }

    return ks_is_certificate_entry(ctx, alias);
}

int64_t JoKS_GetCreationDate(ks_ctx *ctx, const char *alias, size_t alias_len, int32_t *err, int32_t err_len) {
    /* err is jostle's own, so a null or empty one is a broken invariant
     * rather than caller data: abort here instead of reporting it. */
    jo_assert(err != NULL);
    jo_assert(err_len >= 1);
    if (ctx == NULL) {
        *err = JO_KS_CTX_IS_NULL;
        return 0;
    }
    if (ks_ctx_check(ctx) != JO_SUCCESS) {
        *err = JO_KS_CTX_WRONG_KIND;
        return 0;
    }
    if (alias == NULL) {
        *err = JO_KS_ALIAS_IS_NULL;
        return 0;
    }
    if (has_nul(alias, alias_len)) {
        *err = JO_KS_NAME_HAS_NUL;
        return 0;
    }

    return ks_get_creation_date(ctx, alias, err);
}
