//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include <stddef.h>
#include <stdint.h>
#include "types.h"
#include "../util/kdf.h"
#include "../util/bc_err_codes.h"


int32_t JoKDF_PBKDF2(
    uint8_t *passwd, size_t passwd_len,
    uint8_t *salt, size_t salt_len,
    int32_t iter,
    uint8_t *digest_name,
    size_t digest_name_len,
    uint8_t *output,
    size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code = JO_FAIL;

    if (passwd == NULL) {
        ret_code = JO_KDF_PASSWORD_NULL;
        goto exit;
    }

    if (salt == NULL) {
        ret_code = JO_KDF_SALT_NULL;
        goto exit;
    }

    if (salt_len == 0) {
        ret_code = JO_KDF_SALT_EMPTY;
        goto exit;
    }

    if (iter < 0) {
        ret_code = JO_KDF_PBE_ITER_NEGATIVE;
        goto exit;
    }

    if (output == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_offset < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(out_size, out_offset, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (digest_name == NULL) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }


    if (digest_name_len == 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    uint8_t *out = output + out_offset;

    ret_code = jo_pbkdf2(
        passwd, passwd_len,
        salt, salt_len,
        iter,
        digest_name,
        digest_name_len,
        out, out_len);


exit:
    return ret_code;
}


// Jo-prefixed per the FFI symbol-collision rule (native-code.md): a KDF export
// name generic enough to shadow (or be shadowed by) another in-process library
// must carry the Jo prefix. Applies to all three entry points.
int32_t JoKDF_HKDF(
    uint8_t *ikm, size_t ikm_len,
    uint8_t *salt, size_t salt_len,
    uint8_t *info, size_t info_len,
    uint8_t *digest_name, size_t digest_name_len,
    uint8_t *output, size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code = JO_FAIL;

    if (ikm == NULL) {
        ret_code = JO_KDF_HKDF_IKM_NULL;
        goto exit;
    }

    // salt and info are optional (NULL accepted); no null-check here.

    if (output == NULL) {
        ret_code = JO_OUTPUT_IS_NULL;
        goto exit;
    }

    if (out_offset < 0) {
        ret_code = JO_OUTPUT_OFFSET_IS_NEGATIVE;
        goto exit;
    }

    if (out_len < 0) {
        ret_code = JO_OUTPUT_LEN_IS_NEGATIVE;
        goto exit;
    }

    if (!check_in_range(out_size, out_offset, out_len)) {
        ret_code = JO_OUTPUT_OUT_OF_RANGE;
        goto exit;
    }

    if (digest_name == NULL) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    if (digest_name_len == 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    uint8_t *out = output + out_offset;

    ret_code = jo_hkdf(
        ikm, ikm_len,
        salt, salt_len,
        info, info_len,
        digest_name, digest_name_len,
        out, out_len);


exit:
    return ret_code;
}


/*
 * Output-buffer checks shared by the three WI-4 KDF entry points. Kept as one
 * helper because all three take an identical (output, out_size, out_offset,
 * out_len) tail and must reject identically - a divergence between them would
 * be a bug the JNI/FFI parity tests could not see, since both bridges would
 * carry the same drift.
 *
 * out_len == 0 is refused here and not left to OpenSSL: SSHKDF accepts a
 * zero-length request on every supported environment and emits a zero-length
 * key (see kdf_probe.c conclusion 3).
 */
static int32_t kdf_check_output(uint8_t *output, size_t out_size,
                                int32_t out_offset, int32_t out_len)
{
    if (output == NULL) {
        return JO_OUTPUT_IS_NULL;
    }

    if (out_offset < 0) {
        return JO_OUTPUT_OFFSET_IS_NEGATIVE;
    }

    if (out_len < 0) {
        return JO_OUTPUT_LEN_IS_NEGATIVE;
    }

    if (out_len == 0) {
        return JO_OUTPUT_LEN_IS_ZERO;
    }

    if (!check_in_range(out_size, out_offset, out_len)) {
        return JO_OUTPUT_OUT_OF_RANGE;
    }

    return JO_SUCCESS;
}


int32_t JoKDF_KBKDF(
    uint8_t *mode_name, size_t mode_name_len,
    uint8_t *mac_name, size_t mac_name_len,
    uint8_t *digest_name, size_t digest_name_len,
    uint8_t *cipher_name, size_t cipher_name_len,
    uint8_t *key, size_t key_len,
    uint8_t *label, size_t label_len,
    uint8_t *context, size_t context_len,
    uint8_t *seed, size_t seed_len,
    int32_t r,
    int32_t use_l,
    int32_t use_separator,
    uint8_t *output, size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code = JO_FAIL;

    if (mode_name == NULL || mode_name_len == 0) {
        ret_code = JO_KDF_UNKNOWN_MODE;
        goto exit;
    }

    if (mac_name == NULL || mac_name_len == 0) {
        ret_code = JO_KDF_UNKNOWN_MAC;
        goto exit;
    }

    // Exactly which of digest/cipher is required depends on the MAC, and that
    // is the MAC implementation's question - but neither being supplied can
    // never be right, so it is caught here rather than as an opaque EVP error.
    if ((digest_name == NULL || digest_name_len == 0)
            && (cipher_name == NULL || cipher_name_len == 0)) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    if (key == NULL) {
        ret_code = JO_KDF_SECRET_NULL;
        goto exit;
    }

    // label, context and seed are optional (NULL accepted); no null-check here.

    ret_code = kdf_check_output(output, out_size, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_kbkdf(
        mode_name, mode_name_len,
        mac_name, mac_name_len,
        (digest_name_len == 0) ? NULL : digest_name, digest_name_len,
        (cipher_name_len == 0) ? NULL : cipher_name, cipher_name_len,
        key, key_len,
        label, label_len,
        context, context_len,
        seed, seed_len,
        r, use_l, use_separator,
        output + out_offset, out_len);

exit:
    return ret_code;
}


int32_t JoKDF_SSKDF(
    uint8_t *digest_name, size_t digest_name_len,
    uint8_t *secret, size_t secret_len,
    uint8_t *info, size_t info_len,
    uint8_t *output, size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code = JO_FAIL;

    if (digest_name == NULL || digest_name_len == 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    if (secret == NULL) {
        ret_code = JO_KDF_SECRET_NULL;
        goto exit;
    }

    // info is optional (NULL accepted); no null-check here.

    ret_code = kdf_check_output(output, out_size, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_sskdf(
        digest_name, digest_name_len,
        secret, secret_len,
        info, info_len,
        output + out_offset, out_len);

exit:
    return ret_code;
}


int32_t JoKDF_SSHKDF(
    uint8_t *digest_name, size_t digest_name_len,
    uint8_t *key, size_t key_len,
    uint8_t *xcghash, size_t xcghash_len,
    uint8_t *session_id, size_t session_id_len,
    uint8_t *type_name, size_t type_name_len,
    uint8_t *output, size_t out_size,
    int32_t out_offset,
    int32_t out_len
) {
    int32_t ret_code = JO_FAIL;

    if (digest_name == NULL || digest_name_len == 0) {
        ret_code = JO_KDF_PBE_UNKNOWN_DIGEST;
        goto exit;
    }

    if (key == NULL) {
        ret_code = JO_KDF_SECRET_NULL;
        goto exit;
    }

    // RFC 4253 7.2 makes H and the session id mandatory - there is no defined
    // absent form, so unlike a salt or an info string a null is an error.
    if (xcghash == NULL) {
        ret_code = JO_KDF_SSHKDF_XCGHASH_NULL;
        goto exit;
    }

    if (session_id == NULL) {
        ret_code = JO_KDF_SSHKDF_SESSION_ID_NULL;
        goto exit;
    }

    if (type_name == NULL || type_name_len == 0) {
        ret_code = JO_KDF_SSHKDF_TYPE_INVALID;
        goto exit;
    }

    ret_code = kdf_check_output(output, out_size, out_offset, out_len);
    if (UNSUCCESSFUL(ret_code)) {
        goto exit;
    }

    ret_code = jo_sshkdf(
        digest_name, digest_name_len,
        key, key_len,
        xcghash, xcghash_len,
        session_id, session_id_len,
        type_name, type_name_len,
        output + out_offset, out_len);

exit:
    return ret_code;
}
