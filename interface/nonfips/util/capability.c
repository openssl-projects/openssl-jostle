//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "capability.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#include "jo_assert.h"
#include "rand/jostle_lib_ctx.h"

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
