#ifndef RAND_PROV_H
#define RAND_PROV_H

#include <openssl/crypto.h>
#include <openssl/types.h>

#include "rand_upcall.h"

typedef struct jostle_lib_ctx {
    OSSL_LIB_CTX *ossl_libctx;
    EVP_RAND_CTX *rand_ctx;
} jostle_lib_ctx;

/**
 * Create a new jostle_lib_ctx and set **rnd_ctx.
 * @param rnd_ctx receiver of the new context.
 * @param name the name of the OpenSSL module to load.
 * @return JO_SUCCESS or other JO_xx code.
 */
int32_t jostle_ctx_init_new(jostle_lib_ctx **rnd_ctx, const char *name);


/**
 * Free a jostle_lib_ctx: OSSL_LIB_CTX (unloads providers, releases rand_ctx
 * refs) and the wrapper struct. Safe with NULL. Failure-path rollback only;
 * not a general teardown primitive.
 */
void jostle_ctx_destroy(jostle_lib_ctx *ctx);


/**
 * Set the global jostle lib ctx, expected to be called once
 * during java provider startup but does not enforce that.
 * Initialises a thread local
 * @param new_ctx
 * @return 1 on success
 */
int32_t set_global_jostle_lib_ctx(jostle_lib_ctx *new_ctx);


OSSL_LIB_CTX *get_global_jostle_ossl_lib_ctx(void);

/**
 * Set the source of entropy for this call.
 *
 * @param target the target to get entropy from
 */
void rand_set_java_srand_call(void *target);


#endif //RAND_PROV_H
