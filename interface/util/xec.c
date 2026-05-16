//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

// OPS offset map (range 4000-4003): xec_generate_key 4000/4001/4002/4003
// (ctx-new / keygen-init / keygen / post-keygen NULL-key check), with
// flags OPS_OPENSSL_ERROR_1..._4. Note that kdf.c::x963kdf also
// uses the 4000-block (offsets 4000-4002) but with flags
// OPS_OPENSSL_ERROR_7..._9; CLAUDE.md explicitly permits cross-file
// offset reuse — tests target by (file context, flag) pairs and the
// flag sets are disjoint between these two files.

#include "xec.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


/**
 * Probe whether OpenSSL knows the given Montgomery curve name. Uses
 * EVP_PKEY_CTX_new_from_name because X25519 and X448 are distinct
 * EVP_PKEY types — they're not reachable through the `EC` provider's
 * named-group mechanism that ec_curve_supported uses.
 */
int32_t xec_curve_supported(const char *curve_name) {
    jo_assert(curve_name != NULL);

    int32_t ret = JO_CURVE_NOT_SUPPORTED;
    EVP_PKEY_CTX *ctx = NULL;

    ERR_clear_error();

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     curve_name, NULL);
    if (ctx == NULL) {
        goto exit;
    }
    // Defensive: a context obtained by name might exist but not support
    // keygen (e.g. an obscure provider). Run keygen_init as the probe.
    if (1 != EVP_PKEY_keygen_init(ctx)) {
        goto exit;
    }

    ret = 1;

exit:
    EVP_PKEY_CTX_free(ctx);
    // Suppress the error queue: an "unknown algorithm" lookup leaves a
    // benign error that the caller doesn't care about — clearing it
    // keeps the queue clean for the next operation.
    ERR_clear_error();
    return ret;
}


/**
 * X25519 / X448 key generation. The "curve" name is also the OpenSSL
 * EVP_PKEY type name (unlike EC where the type is "EC" and the curve
 * is a separate group parameter).
 *
 * <p>OPS-instrumented at the three OpenSSL call sites with offsets in
 * the 4000 block (4000/4001/4002 for ctx-new/keygen-init/keygen, plus
 * 4003 for the post-keygen NULL-key check).
 */
int32_t xec_generate_key(key_spec *spec, const char *curve_name,
                         void *rnd_src) {
    jo_assert(spec != NULL);
    jo_assert(curve_name != NULL);
    jo_assert(rnd_src != NULL);

    rand_set_java_srand_call(rnd_src);
    ERR_clear_error();

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(),
                                     curve_name, NULL);
    if (OPS_OPENSSL_ERROR_1 ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(4000);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_2 1 != EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(4001);
        goto exit;
    }

    // X25519 / X448 do NOT take an OSSL_PKEY_PARAM_GROUP_NAME parameter
    // — the EVP_PKEY type itself encodes the curve. Pass straight to
    // EVP_PKEY_keygen.

    if (OPS_OPENSSL_ERROR_3 1 != EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(4002);
        goto exit;
    }

    if (OPS_OPENSSL_ERROR_4 spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_4(4003);
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    EVP_PKEY_CTX_free(ctx);
    return ret_code;
}
