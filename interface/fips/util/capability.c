//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "capability.h"

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"

/*
 * The FIPS provider is loaded into this library's lib ctx under this name by
 * jostle_ctx_init_fips. Not caller-supplied — the Java layer's providerName
 * names the module FILE for the search path, while OSSL_PROVIDER_load here
 * needs the name it was activated under in the config, which the config
 * wrapper fixes as "fips".
 */
#define FIPS_PROVIDER_NAME "fips"

int32_t capability_can_fetch(int32_t op_type, const char *name) {
    // Bridge-validated invariants: both bridges null-check the name and
    // range-check the op type before this runs.
    jo_assert(name != NULL);
    jo_assert(op_type >= JO_CAP_OP_MIN && op_type <= JO_CAP_OP_MAX);

    OSSL_LIB_CTX *libctx = get_global_jostle_ossl_lib_ctx();
    int32_t found = 0;

    // Scoped so a failed fetch cannot leave "unsupported algorithm" noise on
    // the queue for an unrelated call to report as its own error. A negative
    // answer is a legitimate result here, not an error.
    ERR_set_mark();

    switch (op_type) {
        case JO_CAP_OP_KEYMGMT: {
            EVP_KEYMGMT *o = EVP_KEYMGMT_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_KEYMGMT_free(o);
            break;
        }
        case JO_CAP_OP_KEYEXCH: {
            EVP_KEYEXCH *o = EVP_KEYEXCH_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_KEYEXCH_free(o);
            break;
        }
        case JO_CAP_OP_SIGNATURE: {
            EVP_SIGNATURE *o = EVP_SIGNATURE_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_SIGNATURE_free(o);
            break;
        }
        case JO_CAP_OP_ASYM_CIPHER: {
            EVP_ASYM_CIPHER *o = EVP_ASYM_CIPHER_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_ASYM_CIPHER_free(o);
            break;
        }
        case JO_CAP_OP_MD: {
            EVP_MD *o = EVP_MD_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_MD_free(o);
            break;
        }
        case JO_CAP_OP_CIPHER: {
            EVP_CIPHER *o = EVP_CIPHER_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_CIPHER_free(o);
            break;
        }
        case JO_CAP_OP_KDF: {
            EVP_KDF *o = EVP_KDF_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_KDF_free(o);
            break;
        }
        case JO_CAP_OP_MAC: {
            EVP_MAC *o = EVP_MAC_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_MAC_free(o);
            break;
        }
        default: {
            // JO_CAP_OP_RAND. The bridges bound op_type to
            // [JO_CAP_OP_MIN, JO_CAP_OP_MAX] and the asserts above restate
            // it, so no other value reaches here.
            EVP_RAND *o = EVP_RAND_fetch(libctx, name, NULL);
            found = o != NULL;
            EVP_RAND_free(o);
            break;
        }
    }

    ERR_pop_to_mark();
    return found;
}

int32_t capability_module_version(char *out, size_t out_len) {
    // Bridge-validated invariant: both bridges supply a real buffer.
    jo_assert(out != NULL);
    jo_assert(out_len > 0);

    out[0] = '\0';

    OSSL_PROVIDER *prov = OSSL_PROVIDER_load(get_global_jostle_ossl_lib_ctx(),
                                             FIPS_PROVIDER_NAME);
    if (prov == NULL) {
        ERR_clear_error();
        return JO_FIPS_PROVIDER_UNAVAILABLE;
    }

    // utf8_ptr, not utf8_string: the provider hands back pointers to its own
    // storage, which is valid while the provider is loaded. Both are copied
    // into the caller's buffer below before the reference is dropped.
    const char *name = NULL;
    const char *version = NULL;
    OSSL_PARAM req[3];
    req[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **) &name, 0);
    req[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **) &version, 0);
    req[2] = OSSL_PARAM_construct_end();

    int32_t ret;
    if (1 != OSSL_PROVIDER_get_params(prov, req) || name == NULL || version == NULL) {
        ERR_clear_error();
        ret = JO_OPENSSL_ERROR;
        goto exit;
    }

    // snprintf, never strcpy/strcat: truncates rather than overruns, and
    // always NUL terminates when out_len > 0.
    int written = snprintf(out, out_len, "%s %s", name, version);
    if (written < 0) {
        out[0] = '\0';
        ret = JO_FAIL;
        goto exit;
    }
    // A truncated write reports the bytes actually in the buffer, not the
    // length snprintf would have needed.
    ret = (size_t) written >= out_len ? (int32_t) (out_len - 1) : (int32_t) written;

exit:
    OSSL_PROVIDER_unload(prov);
    return ret;
}
