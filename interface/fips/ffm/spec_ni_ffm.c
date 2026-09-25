//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <string.h>
#include <openssl/evp.h>

#include "types.h"
#include <openssl/provider.h>

#include "../util/key_spec.h"
#include "../util/bc_err_codes.h"
#include "../util/encapdecap.h"
#include "../util/jo_assert.h"

/*
  Clean up and free a PKEY
 */
void JoSpec_disposeKeySpec(key_spec *ctx) {
    if (ctx == NULL) {
        return;
    }
    free_key_spec(ctx);
}

key_spec *JoSpec_allocateKeySpec(int32_t *err) {
    jo_assert(err != NULL);
    key_spec *spec = create_spec();
    *err = JO_SUCCESS;
    return spec;
}


int32_t JoSpec_Encap(
    key_spec *ks,
    const char *opp,
    uint8_t *input, const size_t input_size, const int32_t in_off, const int32_t in_len,
    uint8_t *output, const size_t output_size, const int32_t out_off, const int32_t out_len,
    void *rand_src
) {
    if (ks == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    if (ks->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }

    int32_t ret = 0;

    if (in_off < 0) {
        ret = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_size, in_off, in_len)) {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *out = NULL;
    if (output != NULL) {
        if (out_off < 0) {
            ret = JO_OUTPUT_OFFSET_IS_NEGATIVE;
            goto exit;
        }

        if (out_len < 0) {
            ret = JO_OUTPUT_LEN_IS_NEGATIVE;
            goto exit;
        }

        if (!check_in_range(output_size, out_off, out_len)) {
            ret = JO_OUTPUT_OUT_OF_RANGE;
            goto exit;
        }
        out = (uint8_t *) output + out_off;
    }

    uint8_t *in = input + (size_t) in_off;

    ret = encap(ks, opp, in, in_len, out, out_len, rand_src);

exit:
    return ret;
}


int32_t JoSpec_Decap(
    key_spec *ks,
    const char *opp,
    uint8_t *input, const size_t input_size, const int32_t in_off, const int32_t in_len,
    uint8_t *output, const size_t output_size, const int32_t out_off, const int32_t out_len,
    void *rand_src
) {
    if (ks == NULL) {
        return JO_KEY_SPEC_IS_NULL;
    }

    if (ks->key == NULL) {
        return JO_KEY_SPEC_HAS_NULL_KEY;
    }

    if (input == NULL) {
        return JO_INPUT_IS_NULL;
    }

    int32_t ret = 0;

    if (in_off < 0) {
        ret = JO_INPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (in_len < 0) {
        ret = JO_INPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(input_size, in_off, in_len)) {
        ret = JO_INPUT_OUT_OF_RANGE;
        goto exit;
    }

    uint8_t *out = NULL;
    if (output != NULL) {
        if (out_off < 0) {
            ret = JO_OUTPUT_OFFSET_IS_NEGATIVE;
            goto exit;
        }

        if (out_len < 0) {
            ret = JO_OUTPUT_LEN_IS_NEGATIVE;
            goto exit;
        }

        if (!check_in_range(output_size, out_off, out_len)) {
            ret = JO_OUTPUT_OUT_OF_RANGE;
            goto exit;
        }
        out = (uint8_t *) output + out_off;
    }

    uint8_t *in = input + in_off;

    ret = decap(ks, opp, in, in_len, out, out_len, rand_src);

exit:
    return ret;
}

const char *JoSpec_GetName(key_spec *ks, size_t *len) {
    jo_assert(len != NULL);
    if (ks == NULL || ks->key == NULL) {
        *len = 0;
        return NULL;
    }

    const char *ret = EVP_PKEY_get0_type_name(ks->key);
    if (ret == NULL) {
        *len = 0;
    } else {
        *len = strlen(ret);
    }
    return ret;
}

/*
 * The name of the OSSL_PROVIDER that owns this KEY's keymgmt.
 *
 * NOT the same question as capability_implementing_provider, which asks which
 * provider implements a NAME in a lib ctx. A key carries its own keymgmt,
 * fixed at creation, and an operation on it is served THERE regardless of the
 * lib ctx the operation was driven through - measured in
 * fips-c-review/probes/xprovider_key_probe.c. That is the fact MT-14 exists to
 * pin, and only a key-level accessor can express it.
 *
 * Same shape as JoSpec_GetName: borrowed pointer, length out-parameter, NULL
 * with *len = 0 when there is nothing to report. The provider name is owned by
 * the provider, which the lib ctx keeps loaded for its own lifetime.
 */
const char *JoSpec_GetKeyProvider(key_spec *ks, size_t *len) {
    jo_assert(len != NULL);
    if (ks == NULL || ks->key == NULL) {
        *len = 0;
        return NULL;
    }

    const OSSL_PROVIDER *prov = EVP_PKEY_get0_provider(ks->key);
    if (prov == NULL) {
        *len = 0;
        return NULL;
    }

    const char *ret = OSSL_PROVIDER_get0_name(prov);
    if (ret == NULL) {
        *len = 0;
    } else {
        *len = strlen(ret);
    }
    return ret;
}
