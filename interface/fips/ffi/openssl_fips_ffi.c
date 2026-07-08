//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "openssl_fips_ffi.h"


#include <stddef.h>
#include "../util/rand.h"
#include "../util/rand/jostle_fips_ctx.h"
#include "../util/rand/jostle_lib_ctx.h"


/*
 * Initialise the FIPS interface library's lib ctxs (operations + the
 * SecureRandom-backing rand ctx), both with the OpenSSL FIPS module + base
 * provider. The module is dlopen'd by libcrypto itself (search path + config
 * drive the integrity-MAC check and self-tests) - never System.load'ed. (The
 * base library's get_ossl_errors, compiled into this library too, serves
 * error retrieval.)
 */
int32_t JoFips_set_openssl_module(const char *module_dir, const char *prov_name,
                                  const char *config_path) {
    int32_t result = JO_FAIL;

    if (module_dir == NULL || *module_dir == '\0') {
        result = JO_FIPS_MODULE_PATH_INVALID;
        goto exit;
    }

    if (prov_name == NULL) {
        result = JO_PROV_NAME_NULL;
        goto exit;
    }
    if (*prov_name == '\0') {
        result = JO_PROV_NAME_EMPTY;
        goto exit;
    }

    if (config_path == NULL || *config_path == '\0') {
        result = JO_FIPS_CONFIG_PATH_INVALID;
        goto exit;
    }

    // Operations lib ctx first: jostle_ctx_init_fips creates a fresh lib ctx
    // per call and fails cleanly (rolled back) without touching global state,
    // so a bad config / wrong name surfaces the exact JO_FIPS_* code
    // regardless of whether a prior call already succeeded. The separate RAND
    // context (backing SecureRandomSpi, mirroring the base entry) is
    // initialised only after; its first-name-wins guard must not pre-empt the
    // operations-ctx failure codes.
    jostle_lib_ctx *provider_ctx = NULL;
    int32_t rand_created = 0;

    result = jostle_ctx_init_fips(&provider_ctx, module_dir, prov_name, config_path);
    if (UNSUCCESSFUL(result)) {
        goto exit;
    }

    result = rand_init_fips(module_dir, prov_name, config_path, &rand_created);
    if (UNSUCCESSFUL(result)) {
        jostle_ctx_destroy(provider_ctx);
        goto exit;
    }

    result = set_global_jostle_lib_ctx(provider_ctx);
    if (UNSUCCESSFUL(result)) {
        if (rand_created) {
            rand_destroy();
        }
        jostle_ctx_destroy(provider_ctx);
    }

exit:
    return result;
}
