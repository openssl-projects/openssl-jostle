#ifndef RAND_PROV_H
#define RAND_PROV_H

#include <openssl/crypto.h>
#include <openssl/types.h>

#include "rand_upcall.h"

typedef struct jostle_lib_ctx {
    OSSL_LIB_CTX *ossl_libctx;
    EVP_RAND_CTX *rand_ctx;
    uint64_t rc;
    CRYPTO_RWLOCK *rc_lock;
    int64_t up_call_id;
} jostle_lib_ctx;

//
// Global Rand Ctx
//

static jostle_lib_ctx *global_rand_ctx = NULL;
static CRYPTO_THREAD_LOCAL java_srand_id;

/**
 * Create a new jostle_lib_ctx and set **rnd_ctx.
 * @param rnd_ctx receiver of the new context.
 * @param name the name of the OpenSSL module to load.
 * @return JO_SUCCESS or other JO_xx code.
 */
int32_t jostle_ctx_init_new(jostle_lib_ctx **rnd_ctx, const char *name);


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
 * @return
 */
void rand_set_java_srand_call(void *target);

#ifdef JOSTLE_OPS
static int last_rand_rc = 0;
#endif

#endif //RAND_PROV_H
