//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#include "openssl_fips_ffi.h"


#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/err.h>

#include <stddef.h>
#include "../util/capability_fips.h"
#include "../util/jo_assert.h"
#include "../util/rand.h"
#include "../util/rand/jostle_fips_ctx.h"
#include "../util/rand/jostle_lib_ctx.h"


/*
 * Initialise the FIPS interface library's lib ctxs (operations + the
 * SecureRandom-backing rand ctx), both with the OpenSSL FIPS module + base
 * provider. The module is dlopen'd by libcrypto itself (search path + config
 * drive the integrity-MAC check and self-tests) - never System.load'ed.
 */
int32_t JoFIPS_set_openssl_module(const char *module_dir, const char *prov_name,
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

    result = set_global_jostle_fips_lib_ctx(provider_ctx);
    if (UNSUCCESSFUL(result)) {
        if (rand_created) {
            rand_destroy();
        }
        jostle_ctx_destroy(provider_ctx);
    }

exit:
    return result;
}

/*
 * Capability probes. Bridge responsibilities per the project rules: null-check
 * the caller-supplied name, range-check the caller-supplied op type, and
 * surface both as typed codes — never let either reach a util jo_assert.
 */
int32_t JoFIPS_can_fetch(int32_t op_type, const char *name) {
    if (name == NULL) {
        return JO_NAME_IS_NULL;
    }
    if (op_type < JO_CAP_OP_MIN || op_type > JO_CAP_OP_MAX) {
        return JO_UNEXPECTED_STATE;
    }
    return capability_can_fetch(op_type, name);
}

int32_t JoFIPS_module_version(char *out, int32_t out_len) {
    if (out == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (out_len <= 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }
    return capability_module_version(out, (size_t) out_len);
}

int32_t JoFIPS_implementing_provider(int32_t op_type, const char *name,
                                     char *out, int32_t out_len) {
    if (name == NULL) {
        return JO_NAME_IS_NULL;
    }
    if (out == NULL) {
        return JO_OUTPUT_IS_NULL;
    }
    if (out_len <= 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }
    if (op_type < JO_CAP_OP_MIN || op_type > JO_CAP_OP_MAX) {
        return JO_UNEXPECTED_STATE;
    }
    return capability_implementing_provider(op_type, name, out, (size_t) out_len);
}


/*
 * Drain this library's thread-local OpenSSL error queue into a NUL-terminated
 * heap string; *len receives the allocation size including the terminator.
 * Caller (Java) owns the result and frees it with JoFFI_freeUnsecureNullSafe.
 *
 * Deliberately implemented here rather than re-including the base tree's
 * openssl_ffi.c twin, which is how the FIPS library used to obtain it. That
 * twin also defines JoOpenSSL_setModule, which builds a lib ctx via
 * jostle_ctx_init_new - no fipsinstall config, no fips=yes default
 * properties - and installs it as this library's global. Nothing bound it, but
 * it was an exported entry point whose only possible effect was to make FIPS
 * fetches resolve to mainline. The JNI side never carried it (fips/jni holds
 * only openssl_fips_jni.c, with its own getOSSLErrors); this brings FFI into
 * line. Do not reintroduce the twin to save these twenty lines.
 */
char *JoFIPS_get_openssl_errors(uint64_t *len) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        // Allocation failure: return a usable diagnostic string instead of
        // crashing in ERR_print_errors below. Caller frees.
        static const char msg[] = "bio was null";
        *len = sizeof(msg);
        char *ret = calloc(*len, 1);
        jo_assert(ret != NULL);
        memcpy(ret, msg, sizeof(msg));
        return ret;
    }
    ERR_print_errors(bio);
    char *buf = NULL;
    size_t size = BIO_get_mem_data(bio, &buf);
    *len = size + 1; // Overallocating by 1 to add trailing zero
    char *ret = calloc(*len, 1);
    jo_assert(ret != NULL);
    if (size > 0) {
        memcpy(ret, buf, size);
    }
    BIO_free(bio);
    return ret; /* Now, Owned by Java side. */
}
