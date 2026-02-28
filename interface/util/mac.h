#ifndef MAC_H
#define MAC_H
#include <openssl/types.h>
#include <stdlib.h>

typedef struct mac_ctx {
    const EVP_MAC *type;
    EVP_MAC_CTX *mac_ctx;
} mac_ctx;

mac_ctx *mac_ctx_alloc(const char *type, int32_t *err);

void mac_ctx_free(mac_ctx *ctx);

int32_t mac_ctx_init(const mac_ctx *ctx, uint8_t *key, size_t key_len, const char *digest, const char *cipher);

int32_t mac_ctx_update(const mac_ctx *ctx, const uint8_t *data, size_t data_len);

int32_t mac_ctx_final(const mac_ctx *ctx, uint8_t *mac, size_t mac_len);

void mac_ctx_reset(mac_ctx *ctx);

#endif //MAC_H
