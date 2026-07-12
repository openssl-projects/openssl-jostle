#include "jostle_lib_ctx.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/provider.h>

#include "../bc_err_codes.h"
#include "../jo_assert.h"


static jostle_lib_ctx *global_rand_ctx = NULL;
static CRYPTO_THREAD_LOCAL java_srand_id;


// FIPS-tree note: this file deliberately contains NO java_rand_bridge
// provider. The nonfips twin registers a bridge EVP_RAND so caller-supplied
// Java entropy backs every OpenSSL RAND draw; the FIPS provider must not —
// module-internal operations draw from the validated module's own DRBG
// chain and never consult the outer lib ctx's RAND (probe-confirmed; see
// the entropy-contract notes around jostle_ctx_init_fips). The bridge code
// that used to sit here as dead weight was removed so it cannot be wired in
// by accident; do not reintroduce it. What remains live:
//
//   1. jostle_ctx_init_new / jostle_ctx_destroy — plain lib ctx lifecycle
//      (bridge-less). Reached only through the base-named FFI init export
//      (ffi/openssl_ffi.c, part of the shared FFI glue set); the JSLFIPS
//      Java classes always use jostle_ctx_init_fips instead.
//   2. set_global_jostle_lib_ctx / get_global_jostle_ossl_lib_ctx — the
//      provider-wide lib ctx accessor used by every util module.
//   3. rand_set_java_srand_call — sets the per-thread up-call target. The
//      bridge glue calls it on every entropy-accepting entry point (the
//      util twins are byte-identical across trees), but in the FIPS tree
//      nothing ever reads the thread-local: no consumer exists by design.


int32_t jostle_ctx_init_new(jostle_lib_ctx **ctx, const char *name) {
    jo_assert(ctx != NULL);
    jo_assert(name != NULL);

    jostle_lib_ctx *new_ctx = OPENSSL_zalloc(sizeof(jostle_lib_ctx));
    jo_assert(new_ctx != NULL);

    // Bridge-less by design (see the FIPS-tree note above): a fresh lib ctx
    // with only the named provider loaded. Soft-error path: the provider
    // failing to load rolls back so the caller can retry.
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    jo_assert(libctx != NULL);

    OSSL_PROVIDER *provider = OSSL_PROVIDER_load(libctx, name);
    if (provider == NULL) {
        OSSL_LIB_CTX_free(libctx);
        OPENSSL_free(new_ctx);
        *ctx = NULL;
        return JO_OPENSSL_ERROR;
    }

    new_ctx->ossl_libctx = libctx;
    *ctx = new_ctx;

    return JO_SUCCESS;
}


void jostle_ctx_destroy(jostle_lib_ctx *ctx) {
    if (ctx == NULL) {
        return;
    }
    // Freeing the lib ctx unloads its providers.
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
 * Getter for the underlying OSSL_LIB_CTX (FIPS tree: no rand bridge).
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
 * FIPS tree: retained because every entropy-accepting entry point in the
 * byte-identical util twins calls it, but nothing here ever reads the
 * thread-local — the validated module manages its own entropy (see the
 * FIPS-tree note at the top of this file).
 *
 * @param target, FFI created function pointer, JNI pass jobject
 *
 */
void rand_set_java_srand_call(void *target) {
    jo_assert(target != NULL);
    jo_assert(CRYPTO_THREAD_set_local(&java_srand_id, target)!=0);
}
