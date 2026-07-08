//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//

#include "jostle_fips_ctx.h"

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "../bc_err_codes.h"
#include "../jo_assert.h"
#include "../ops.h"


// All file-path handling (deriving the module directory from the module
// path, the provider name from the file name, defaulting the config path)
// happens on the Java side, which has real path APIs; the bridge validates
// the strings (null/empty -> JO_FIPS_MODULE_PATH_INVALID etc.) and util
// asserts them as invariants.
int32_t jostle_fips_configure_libctx(OSSL_LIB_CTX *libctx, const char *module_dir,
                                     const char *prov_name, const char *config_path) {
    jo_assert(libctx != NULL);
    jo_assert(module_dir != NULL);
    jo_assert(prov_name != NULL);
    jo_assert(config_path != NULL);

    int32_t ret_code = JO_SUCCESS;
    BIO *conf_bio = NULL;
    CONF *conf = NULL;
    EVP_MD *probe = NULL;

    ERR_clear_error();

    // Tell libcrypto where to dlopen provider modules from - the compiled-in
    // MODULESDIR points at the build machine, never the deploy host.
    jo_assert(1 == OSSL_PROVIDER_set_default_search_path(libctx, module_dir));

    // The fipsinstall-generated config carries only [fips_sect] (module-mac,
    // activate, self-test switches); it does not activate anything by itself.
    // Wrap it in a synthesised activating configuration: include it, map the
    // provider name to fips_sect, and activate the base provider (built into
    // libcrypto) alongside it for encoders/decoders.
    conf_bio = BIO_new(BIO_s_mem());
    jo_assert(conf_bio != NULL);
    // config_diagnostics makes provider-activation failures (module not
    // found, integrity-MAC mismatch, self-test failure) fail the config
    // load itself with details on the ERR queue, instead of being silently
    // swallowed and only surfacing later as provider-unavailable.
    jo_assert(0 < BIO_printf(conf_bio,
                             "config_diagnostics = 1\n"
                             "openssl_conf = openssl_init\n"
                             ".include %s\n"
                             "[openssl_init]\n"
                             "providers = provider_sect\n"
                             "[provider_sect]\n"
                             "%s = fips_sect\n"
                             "base = base_sect\n"
                             "[base_sect]\n"
                             "activate = 1\n",
                             config_path, prov_name));

    conf = NCONF_new_ex(libctx, NULL);
    jo_assert(conf != NULL);

    // Config load activates the providers: the FIPS module is located on the
    // search path, dlopen'd by libcrypto, its integrity MAC verified against
    // module-mac and its self-tests run. Any of those failing fails the load.
    if (OPS_OPENSSL_ERROR_1 0 >= NCONF_load_bio(conf, conf_bio, NULL)) {
        ret_code = JO_FIPS_CONFIG_LOAD_FAILED;
        goto exit;
    }
    if (OPS_OPENSSL_ERROR_2 0 >= CONF_modules_load(conf, NULL, 0)) {
        ret_code = JO_FIPS_CONFIG_LOAD_FAILED;
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_3 1 != OSSL_PROVIDER_available(libctx, prov_name)) {
        ret_code = JO_FIPS_PROVIDER_UNAVAILABLE;
        goto exit;
    }
    if (OPS_OPENSSL_ERROR_4 1 != OSSL_PROVIDER_available(libctx, "base")) {
        ret_code = JO_FIPS_BASE_UNAVAILABLE;
        goto exit;
    }

    // Pin the lib ctx to FIPS-approved implementations: every fetch without
    // an explicit property query now resolves with fips=yes, so algorithms
    // the module ships as unapproved (fips=no - e.g. Ed25519, 3DES) cannot
    // be selected. Do not weaken or remove this - it is the approved-mode
    // gate for the whole context.
    if (OPS_OPENSSL_ERROR_5 1 != EVP_default_properties_enable_fips(libctx, 1)) {
        ret_code = JO_FIPS_ENABLE_FAILED;
        goto exit;
    }

    // Health probe: a fips=yes fetch must resolve through the module. Catches
    // a context that loaded but cannot actually serve approved algorithms.
    probe = EVP_MD_fetch(libctx, "SHA-256", NULL);
    if (OPS_OPENSSL_ERROR_6 probe == NULL) {
        ret_code = JO_FIPS_FETCH_PROBE_FAILED;
        goto exit;
    }

exit:
    EVP_MD_free(probe);
    NCONF_free(conf);
    BIO_free(conf_bio);
    return ret_code;
}


int32_t jostle_ctx_init_fips(jostle_lib_ctx **ctx, const char *module_dir,
                             const char *prov_name, const char *config_path) {
    jo_assert(ctx != NULL);

    jostle_lib_ctx *new_ctx = OPENSSL_zalloc(sizeof(jostle_lib_ctx));
    jo_assert(new_ctx != NULL);

    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();
    jo_assert(libctx != NULL);

    int32_t ret_code = jostle_fips_configure_libctx(libctx, module_dir, prov_name, config_path);

    if (UNSUCCESSFUL(ret_code)) {
        // Failure path: freeing the lib ctx unloads any activated providers.
        OSSL_LIB_CTX_free(libctx);
        OPENSSL_free(new_ctx);
        *ctx = NULL;
        return ret_code;
    }

    // No java_rand_bridge in a FIPS context: entropy stays inside the FIPS
    // boundary, served by the module's own approved DRBGs, which OpenSSL
    // auto-instantiates for the lib ctx on first RAND use. rand_ctx stays
    // NULL - jostle_ctx_destroy tolerates that.
    new_ctx->ossl_libctx = libctx;
    *ctx = new_ctx;

    return JO_SUCCESS;
}
