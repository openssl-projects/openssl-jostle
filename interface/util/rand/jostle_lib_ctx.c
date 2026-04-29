#include "jostle_lib_ctx.h"

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <execinfo.h>

#include "../bc_err_codes.h"
#include "../jo_assert.h"
#include "../../jni/types.h"

#include "stdlib.h"
#include "../ops.h"


static jostle_lib_ctx *global_rand_ctx = NULL;
static CRYPTO_THREAD_LOCAL java_srand_id;


// OSSL_FUNC_PROVIDER_TEARDOWN
static void jrand_prov_teardown(void *provctx) {
    OPENSSL_free(provctx);
}

// OSSL_FUNC_RAND_INSTANTIATE
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
static int generate(void *vdrbg,
                    unsigned char *out, size_t outlen,
                    unsigned int strength, int prediction_resistance,
                    const unsigned char *adin, size_t adin_len) {
    jostle_lib_ctx *ctx = (jostle_lib_ctx *) vdrbg;

    if (out != NULL) {
        jo_assert(ctx != NULL);
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
static void *new_ctx(void *provctx, void *parent, const OSSL_DISPATCH *parent_calls) {
    UNUSED(provctx);
    UNUSED(parent);
    UNUSED(parent_calls);

    jostle_lib_ctx *ctx = NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    jo_assert(ctx != NULL);
    return ctx;
}


// OSSL_FUNC_RAND_GET_CTX_PARAMS
static int get_ctx_params(ossl_unused void *vctx, OSSL_PARAM params[]) {
    UNUSED(vctx);

    if (params == NULL) {
        return 1;
    }
    int t = 0;
    OSSL_PARAM param = params[t];
    while (param.key != NULL) {
        if (strcmp(params[0].key, OSSL_RAND_PARAM_MAX_REQUEST) == 0) {
            (*(size_t *) (param.data)) = INT_MAX;
        }
        param = params[++t];
    }


    return 1;
}

// OSSL_FUNC_RAND_FREECTX
static int get_ctx_free(void *vdrbg) {
    OPENSSL_free(vdrbg);
    return 1;
}


static const OSSL_DISPATCH jrand_func[] = {
    {OSSL_FUNC_RAND_GENERATE, (void (*)(void)) generate},
    {OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void)) instance},
    {OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void)) uninstance},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void)) free_rand},


    {OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void)) get_ctx_params},
    {OSSL_FUNC_RAND_NEWCTX, (void (*)(void)) new_ctx},
    {OSSL_FUNC_RAND_FREECTX, (void (*)(void)) get_ctx_free},
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
    //
    // Any issues setting the java rand bridge up result in a hard failure.
    // that will shut the VM down.
    //

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    jo_assert(libctx != NULL);
    jo_assert(0 != OSSL_PROVIDER_add_builtin(libctx, "java_rand_bridge", jrand));

    jo_assert(ctx != NULL);
    ctx->ossl_libctx = libctx;

    OSSL_PROVIDER *jrandProv = OSSL_PROVIDER_load(libctx, "java_rand_bridge");
    jo_assert(jrandProv != NULL);


    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, name);
    if (provider == NULL) {
        return JO_OPENSSL_ERROR;
    }


    EVP_RAND *rand = EVP_RAND_fetch(libctx, "JAVA_RAND_BRIDGE", NULL);
    jo_assert(rand != NULL);

    ctx->rand_ctx = EVP_RAND_CTX_new(rand,NULL);
    jo_assert(ctx->rand_ctx != NULL);


    jo_assert(1 == EVP_RAND_instantiate(ctx->rand_ctx, 0, 0, NULL, 0, NULL));
    jo_assert(1 == RAND_set0_private(libctx, ctx->rand_ctx));
    jo_assert(1 == RAND_set0_public(libctx, ctx->rand_ctx));


    return JO_SUCCESS;
}


int32_t jostle_ctx_init_new(jostle_lib_ctx **ctx, const char *name) {
    jostle_lib_ctx *new_ctx = OPENSSL_zalloc(sizeof(jostle_lib_ctx));

    jo_assert(new_ctx != NULL);


    int32_t ret_code = setup_bridge_prov_and_rand(new_ctx, name);

    if (UNSUCCESSFUL(ret_code)) {
        OPENSSL_free(*ctx);
        *ctx = NULL;
        return ret_code;
    }

    *ctx = new_ctx;

    return JO_SUCCESS;
}


int32_t set_global_jostle_lib_ctx(jostle_lib_ctx *new_ctx) {
    if (1 != CRYPTO_THREAD_init_local(&java_srand_id, NULL)) {
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
