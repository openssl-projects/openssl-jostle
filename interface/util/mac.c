#include "mac.h"


#include <stddef.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "jo_assert.h"

mac_ctx *mac_ctx_alloc(const char *type, int32_t *err) {
    if (type == NULL) {
        *err = JO_NAME_IS_NULL;
        return NULL;
    }

    EVP_MAC *mac = EVP_MAC_fetch(NULL, type, NULL);
    if (mac == NULL) {
        *err = JO_NAME_NOT_FOUND;
        return NULL;
    }

    EVP_MAC_CTX *mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL) {
        *err = JO_OPENSSL_ERROR;
        return NULL;
    }


    mac_ctx *ctx = calloc(1, sizeof(*ctx));
    jo_assert(ctx != NULL);

    ctx->type = mac;
    ctx->mac_ctx = mctx;
    return ctx;
}

void mac_ctx_free(mac_ctx *ctx) {
    if (ctx->mac_ctx != NULL) {
        EVP_MAC_CTX_free(ctx->mac_ctx);
    }
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    free(ctx);
}

int32_t mac_ctx_init(const mac_ctx *ctx, uint8_t *key, size_t key_len, const char *digest, const char *cipher) {
    jo_assert(ctx != NULL);


    if (key == NULL) {
        return JO_KEY_IS_NULL;
    }


    OSSL_PARAM params[3] = {OSSL_PARAM_construct_end()};
    int index = 0;
    if (digest != NULL) {
        params[index++] = OSSL_PARAM_construct_utf8_string("digest", (char *) digest, 0);
    }
    if (cipher != NULL) {
        params[index++] = OSSL_PARAM_construct_utf8_string("cipher", (char *) cipher, 0);
    }

    if (1 != EVP_MAC_init(ctx->mac_ctx, key, key_len, params)) {
        return JO_OPENSSL_ERROR;
    }

    return JO_SUCCESS;
}

int32_t mac_ctx_update(const mac_ctx *ctx, const uint8_t *data, size_t data_len) {
    jo_assert(ctx != NULL);

    if (data == NULL) {
        return JO_INPUT_IS_NULL;
    }

    if (!EVP_MAC_update(ctx->mac_ctx, data, data_len)) {
        return JO_OPENSSL_ERROR;
    }
    return (int32_t) data_len;
}

int32_t mac_ctx_final(const mac_ctx *ctx, uint8_t *mac, size_t mac_len) {
    jo_assert(ctx != NULL);
    jo_assert(mac != NULL);
    size_t out_len = 0;
    if (!EVP_MAC_final(ctx->mac_ctx,mac,&out_len,mac_len)) {
        return JO_OPENSSL_ERROR;
    }
    return (int32_t) out_len;
}

void mac_ctx_reset(mac_ctx *ctx) {
    jo_assert(ctx != NULL);
    // TODO not implemented yet
}
