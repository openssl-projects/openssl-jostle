#ifndef RAND_PROV_H
#define RAND_PROV_H

#include <openssl/crypto.h>
#include <openssl/types.h>

#include "rand_upcall.h"

typedef struct jostle_lib_ctx {
    OSSL_LIB_CTX *ossl_libctx;
} jostle_lib_ctx;

/**
 * Create a new jostle_lib_ctx and set **rnd_ctx.
 * @param rnd_ctx receiver of the new context.
 * @param name the name of the OpenSSL module to load.
 * @return JO_SUCCESS or other JO_xx code.
 */
int32_t jostle_ctx_init_new(jostle_lib_ctx **rnd_ctx, const char *name);


/**
 * Free a jostle_lib_ctx: OSSL_LIB_CTX (unloads providers) and the wrapper
 * struct. Safe with NULL. Failure-path rollback only; not a general
 * teardown primitive.
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

/**
 * Clear the per-thread RandSource up-call target. Every entry point that
 * binds a target with rand_set_java_srand_call MUST clear it before
 * returning: the target's lifetime is the duration of that native call (a
 * JNI local ref / an FFI arena-scoped stub), so a stale value read by a
 * future draw outside any entry point would be use-after-free. With the
 * target cleared, such a draw fails typed ("rand_src was null") instead.
 */
void rand_clear_java_srand_call(void);


#endif //RAND_PROV_H
