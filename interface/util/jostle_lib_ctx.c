#include "jostle_lib_ctx.h"

#include <openssl/err.h>
#include <openssl/provider.h>

#include "bc_err_codes.h"
#include "jo_assert.h"

static jostle_lib_ctx *global_jostle_ctx = NULL;

static int32_t setup_provider_libctx(jostle_lib_ctx *ctx, const char *name) {
    jo_assert(ctx != NULL);
    jo_assert(name != NULL);

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    jo_assert(libctx != NULL);

    if (OSSL_PROVIDER_load(libctx, name) == NULL) {
        OSSL_LIB_CTX_free(libctx);
        ctx->ossl_libctx = NULL;
        return JO_OPENSSL_ERROR;
    }

    ctx->ossl_libctx = libctx;
    return JO_SUCCESS;
}

int32_t jostle_ctx_init_new(jostle_lib_ctx **ctx, const char *name) {
    jo_assert(ctx != NULL);

    jostle_lib_ctx *new_ctx = OPENSSL_zalloc(sizeof(jostle_lib_ctx));
    jo_assert(new_ctx != NULL);

    int32_t ret_code = setup_provider_libctx(new_ctx, name);
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
    if (ctx->ossl_libctx != NULL) {
        OSSL_LIB_CTX_free(ctx->ossl_libctx);
    }
    OPENSSL_free(ctx);
}

int32_t set_global_jostle_lib_ctx(jostle_lib_ctx *new_ctx) {
    if (global_jostle_ctx != NULL) {
        ERR_raise_data(ERR_LIB_PROV, ERR_R_INIT_FAIL,
                       "set_global_jostle_lib_ctx already called; provider startup must invoke it once");
        return JO_UNEXPECTED_STATE;
    }

    global_jostle_ctx = new_ctx;
    return JO_SUCCESS;
}

OSSL_LIB_CTX *get_global_jostle_ossl_lib_ctx(void) {
    jo_assert(global_jostle_ctx != NULL);
    return global_jostle_ctx->ossl_libctx;
}
