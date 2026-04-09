//
//   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//   Licensed under the Apache License 2.0 (the "License"). You may not use
//   this file except in compliance with the License.  You can obtain a copy
//   in the file LICENSE in the source distribution or at
//   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//


#include "edec.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "key_spec.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"

int32_t edec_generate_key(key_spec *spec, int32_t type, void *rnd_src) {
    jo_assert(spec != NULL);

    if (rnd_src == NULL) {
        return JO_RAND_NO_RAND_UP_CALL;
    }

    rand_set_java_srand_call(rnd_src);

    int32_t ret_code = JO_FAIL;
    EVP_PKEY_CTX *ctx = NULL;

    switch (type) {
        case KS_ED25519:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "ED25519",NULL);
            break;
        case KS_ED448:
            ctx = EVP_PKEY_CTX_new_from_name(get_global_jostle_ossl_lib_ctx(), "ED448",NULL);
            break;
        default:
            ret_code = JO_INCORRECT_KEY_TYPE;
            goto exit;
    }

    if (ctx == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_keygen_init(ctx)) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    if (!EVP_PKEY_keygen(ctx, &(spec->key))) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

#ifdef JOSTLE_OPS
    if (OPS_OPENSSL_ERROR_1 0) {
        EVP_PKEY_free(spec->key);
        spec->key = NULL;
    }
#endif

    if (spec->key == NULL) {
        ret_code = JO_OPENSSL_ERROR;
        goto exit;
    }

    ret_code = JO_SUCCESS;

exit:
    return ret_code;
}

