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


int32_t jostle_ctx_init_new(jostle_lib_ctx **rnd_ctx, const char *name);

int32_t jostle_ctx_init(jostle_lib_ctx *ctx, const char *name);

int64_t rand_up_call_get_id(void *src);


//
// Global Rand Ctx
//

static jostle_lib_ctx *global_rand_ctx = NULL;
static CRYPTO_THREAD_LOCAL java_srand_id;


/**
 *
 * @param new_ctx new context
 * @return 1 on success, 0 on failure
 */
int32_t set_jostle_ctx(jostle_lib_ctx *new_ctx);

/**
 * increment global rand
 * @return
 */
int32_t get_jostle_ctx(jostle_lib_ctx **ctx);


OSSL_LIB_CTX *get_jostle_ossl_lib_ctx(void);

/**
 * Set the source of entropy for this call.
 *
 * @param target the target to get entropy from
 * @return
 */
int rand_set_java_srand_call(void *target);

#ifdef JOSTLE_OPS
static int last_rand_rc = 0;
#endif

#endif //RAND_PROV_H
