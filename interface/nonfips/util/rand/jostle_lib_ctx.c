#include "jostle_lib_ctx.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include "../bc_err_codes.h"
#include "../jo_assert.h"
#include "../macros.h"
#include "../ops.h"


static jostle_lib_ctx *global_rand_ctx = NULL;
static CRYPTO_THREAD_LOCAL java_srand_id;


// OSSL_FUNC_PROVIDER_TEARDOWN
// provctx is never set by jrand(); free(NULL) is a no-op. Kept to silence
// OpenSSL's "no teardown" warning.
static void jrand_prov_teardown(void *provctx) {
    OPENSSL_free(provctx);
}

// OSSL_FUNC_RAND_INSTANTIATE / OSSL_FUNC_RAND_UNINSTANTIATE
// No-op: thin pass-through to Java RandSource. No DRBG state, no entropy
// pool, no strength validation. Strength check (if any) belongs here.
static int instance(void *vdrbg, unsigned int strength, int prediction_resistance,
                    const unsigned char *adin, size_t adin_len, OSSL_PARAM *params) {
    UNUSED(strength);
    UNUSED(prediction_resistance);
    UNUSED(adin);
    UNUSED(adin_len);
    UNUSED(params);
    UNUSED(vdrbg);


    return 1;
}

// OSSL_FUNC_RAND_UNINSTANTIATE
static int uninstance(void *vdrbg) {
    UNUSED(vdrbg);
    return 1;
}

// OSSL_FUNC_RAND_FREECTX
static int free_rand(void *vdrbg) {
    OPENSSL_free(vdrbg);
    return 1;
}


// OSSL_FUNC_RAND_GENERATE
// out == NULL: no-op success (treat as "ready" probe).
// OPS_OPENSSL_ERROR_1 forces entry with NULL src; OPS_OPENSSL_ERROR_2 forces
// honoring the up-call's negative return. Flag names predate
// OPS_RAND_UP_CALL_NULL, kept for test continuity.
static int generate(void *vdrbg,
                    unsigned char *out, size_t outlen,
                    unsigned int strength, int prediction_resistance,
                    const unsigned char *adin, size_t adin_len) {
    jo_assert(vdrbg != NULL);

    if (out != NULL) {
        void *rand_src = CRYPTO_THREAD_get_local(&java_srand_id);

        if (OPS_OPENSSL_ERROR_1 rand_src != NULL) {
            int rc = rand_up_call_next_bytes(rand_src, out, outlen, strength, prediction_resistance, adin, adin_len);
            if (OPS_OPENSSL_ERROR_2 rc < 0) {
                ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "rand up-call failed with code %d", rc);
                return 0;
            }
        } else {
            ERR_raise_data(ERR_LIB_RAND, ERR_R_RAND_LIB, "rand_src was null");
            return 0;
        }
    }

    return 1;
}

// OSSL_FUNC_RAND_NEWCTX
// State lives in thread-local java_srand_id; vdrbg just needs to be non-NULL
// until FREECTX. 1-byte sentinel.
static void *new_ctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls) {
    UNUSED(provctx);
    UNUSED(parent);
    UNUSED(parent_calls);

    void *ctx = OPENSSL_zalloc(1);
    jo_assert(ctx != NULL);
    return ctx;
}


// OSSL_FUNC_RAND_GET_CTX_PARAMS
// Answers:
//   MAX_REQUEST = INT_MAX (matches up-call int32 cast).
//   STRENGTH    = 256 (advisory — bridge cannot introspect the Java side;
//                      up-call target is per-call thread-local, not bound
//                      to the EVP_RAND_CTX).
// Other DRBG params unanswered. gettable list below mirrors this.
static int get_ctx_params(ossl_unused void *vctx, OSSL_PARAM params[]) {
    UNUSED(vctx);

    if (params == NULL) {
        return 1;
    }
    for (int t = 0; params[t].key != NULL; t++) {
        if (strcmp(params[t].key, OSSL_RAND_PARAM_MAX_REQUEST) == 0) {
            *(size_t *) params[t].data = INT_MAX;
        } else if (strcmp(params[t].key, OSSL_RAND_PARAM_STRENGTH) == 0) {
            *(unsigned int *) params[t].data = 256;
        }
    }


    return 1;
}

// OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS
// Mirror of get_ctx_params. Required for callers that probe via
// OSSL_PARAM_locate before reading.
static const OSSL_PARAM *get_gettable_ctx_params(ossl_unused void *vctx,
                                                 ossl_unused void *provctx) {
    UNUSED(vctx);
    UNUSED(provctx);
    static const OSSL_PARAM gettable[] = {
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_END
    };
    return gettable;
}

static const OSSL_DISPATCH jrand_func[] = {
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void)) generate},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) instance},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) uninstance},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void)) free_rand},
    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) get_ctx_params},
    {OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void (*)(void)) get_gettable_ctx_params},
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) new_ctx},
    {0,NULL}
};

static const OSSL_ALGORITHM rand_def[] = {
    {"JAVA_RAND_BRIDGE", "provider=java_rand_bridge", jrand_func, ""},
    {NULL,NULL,NULL,NULL}
};


// OSSL_FUNC_PROVIDER_QUERY_OPERATION
static const OSSL_ALGORITHM *jrand_query(void *provctx, int operation_id,
                                         int *no_cache) {
    UNUSED(provctx);
    UNUSED(no_cache);
    if (operation_id == OSSL_OP_RAND) {
        return rand_def;
    }
    return NULL;
}

static const OSSL_DISPATCH jrand_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void)) jrand_prov_teardown},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void)) jrand_query},
    OSSL_DISPATCH_END
};

// Provider entry function
static int jrand(const OSSL_CORE_HANDLE *handle,
                 const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                 void **provctx) {
    UNUSED(provctx);
    UNUSED(in);
    UNUSED(handle);
    *out = jrand_dispatch_table;
    return 1;
}


static int32_t setup_bridge_prov_and_rand(jostle_lib_ctx *ctx, const char *name) {
    // Bridge setup failures are hard (jo_assert -> abort). Only soft-error
    // path: user-supplied provider fails to load — roll back libctx + bridge
    // provider so caller can retry.

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    jo_assert(libctx != NULL);
    jo_assert(0 != OSSL_PROVIDER_add_builtin(libctx, "java_rand_bridge", jrand));

    jo_assert(ctx != NULL);
    ctx->ossl_libctx = libctx;

    OSSL_PROVIDER *jrandProv = OSSL_PROVIDER_load(libctx, "java_rand_bridge");
    jo_assert(jrandProv != NULL);


    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, name);
    if (provider == NULL) {
        OSSL_PROVIDER_unload(jrandProv);
        OSSL_LIB_CTX_free(libctx);
        ctx->ossl_libctx = NULL;
        return JO_OPENSSL_ERROR;
    }


    EVP_RAND *rand = EVP_RAND_fetch(libctx, "JAVA_RAND_BRIDGE", NULL);
    jo_assert(rand != NULL);

    ctx->rand_ctx = EVP_RAND_CTX_new(rand,NULL);
    jo_assert(ctx->rand_ctx != NULL);

    // EVP_RAND_CTX_new ups rand's refcount; release ours.
    EVP_RAND_free(rand);


    jo_assert(1 == EVP_RAND_instantiate(ctx->rand_ctx, 0, 0, NULL, 0, NULL));

    // RAND_set0_* consumes the caller's ref. Up-ref between calls so each
    // slot owns one ref; otherwise libctx teardown double-frees.
    jo_assert(1 == RAND_set0_private(libctx, ctx->rand_ctx));
    jo_assert(1 == EVP_RAND_CTX_up_ref(ctx->rand_ctx));
    jo_assert(1 == RAND_set0_public(libctx, ctx->rand_ctx));


    return JO_SUCCESS;
}


int32_t jostle_ctx_init_new(jostle_lib_ctx **ctx, const char *name) {
    jo_assert(ctx != NULL);

    jostle_lib_ctx *new_ctx = OPENSSL_zalloc(sizeof(jostle_lib_ctx));
    jo_assert(new_ctx != NULL);


    int32_t ret_code = setup_bridge_prov_and_rand(new_ctx, name);

    if (UNSUCCESSFUL(ret_code)) {
        OPENSSL_free(new_ctx);
        *ctx = NULL;
        return ret_code;
    }

    *ctx = new_ctx;

    return JO_SUCCESS;
}


void jostle_ctx_destroy(jostle_lib_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    // Freeing libctx unloads its providers and releases the RAND slot refs;
    // rand_ctx needs no explicit free.
    if (ctx->ossl_libctx != NULL) {
        OSSL_LIB_CTX_free(ctx->ossl_libctx);
    }
    OPENSSL_free(ctx);
}

// No provider-unload path today. State held for JVM lifetime, freed at JVM
// shutdown. Future teardown must: clear global_rand_ctx, jostle_ctx_destroy,
// DeleteGlobalRef target_class, CRYPTO_THREAD_cleanup_local java_srand_id.


// CRYPTO_THREAD_init_local is UB on re-init; guard with run_once.
static CRYPTO_ONCE init_local_once = CRYPTO_ONCE_STATIC_INIT;
static int init_local_ok = 0;

static void init_thread_local_once(void) {
    if (1 == CRYPTO_THREAD_init_local(&java_srand_id, NULL)) {
        init_local_ok = 1;
    }
}

int32_t set_global_jostle_lib_ctx(jostle_lib_ctx *new_ctx) {
    // Call once at provider startup. Second call rejected.
    // Check-then-assign on global_rand_ctx is not atomic; concurrent callers
    // may leak a jostle_lib_ctx. Acceptable given single-call contract.
    if (global_rand_ctx != NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                       "set_global_jostle_lib_ctx already called; provider startup must invoke it once");
        return JO_OPENSSL_ERROR;
    }

    if (!CRYPTO_THREAD_run_once(&init_local_once, init_thread_local_once) || !init_local_ok) {
        ERR_add_error_txt(":", "set_jostle_ctx");
        return JO_OPENSSL_ERROR;
    }

    global_rand_ctx = new_ctx;
    return JO_SUCCESS;
}


/**
 * Getter for underlying OSSL_LIB_CTX with java rand bridge installed.
 * Non-mutating, thread safe but no locks, expects set_global_jostle_lib_ctx to have
 * been called with valid jostle_lib_ctx before use.
 * @return an OSSL_LIB_CTX
 */
OSSL_LIB_CTX *get_global_jostle_ossl_lib_ctx(void) {
    jo_assert(global_rand_ctx != NULL);
    return global_rand_ctx->ossl_libctx;
}


/**
 * Use to set the RandSource up-call receiver, FFI callers will pass pointer
 * to FFI constructed function and JNI callers will pass jobject
 *
 * Function expects, to be able to set thread local value, will abort the
 * process if it can not do so.
 *
 * @param target, FFI created function pointer, JNI pass jobject
 *
 */
void rand_set_java_srand_call(void *target) {
    jo_assert(target != NULL);
    jo_assert(CRYPTO_THREAD_set_local(&java_srand_id, target)!=0);
}
