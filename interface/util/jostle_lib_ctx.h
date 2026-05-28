#ifndef JOSTLE_LIB_CTX_H
#define JOSTLE_LIB_CTX_H

#include <openssl/crypto.h>
#include <openssl/types.h>

typedef struct jostle_lib_ctx {
    OSSL_LIB_CTX *ossl_libctx;
} jostle_lib_ctx;

/**
 * Create a new jostle_lib_ctx and set **ctx.
 * @param ctx receiver of the new context.
 * @param name the name of the OpenSSL module to load.
 * @return JO_SUCCESS or other JO_xx code.
 */
int32_t jostle_ctx_init_new(jostle_lib_ctx **ctx, const char *name);


/**
 * Free a jostle_lib_ctx: OSSL_LIB_CTX and the wrapper struct. Safe with NULL.
 */
void jostle_ctx_destroy(jostle_lib_ctx *ctx);


/**
 * Set the global jostle lib ctx, expected to be called once
 * during java provider startup but does not enforce that.
 * @param new_ctx
 * @return 1 on success
 */
int32_t set_global_jostle_lib_ctx(jostle_lib_ctx *new_ctx);


OSSL_LIB_CTX *get_global_jostle_ossl_lib_ctx(void);


#endif //JOSTLE_LIB_CTX_H
