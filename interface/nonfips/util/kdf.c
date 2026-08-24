//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#include "kdf.h"
#include "openssl/kdf.h"


#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "bc_err_codes.h"
#include "jo_assert.h"
#include "ops.h"
#include "rand/jostle_lib_ctx.h"


int32_t jo_pbkdf2(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint32_t iter,
    uint8_t *digest,
    size_t digest_len,
    uint8_t *out,
    size_t out_len
) {
    jo_assert(password != NULL);
    jo_assert(salt != NULL);
    jo_assert(digest != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "PBKDF2", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(2002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);


    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(2000);
        goto exit;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password, password_len),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter),
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len),
        OSSL_PARAM_END
    };

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(2001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}


int32_t jo_hkdf(
    uint8_t *ikm, size_t ikm_len,
    uint8_t *salt, size_t salt_len,
    uint8_t *info, size_t info_len,
    uint8_t *digest, size_t digest_len,
    uint8_t *out, size_t out_len
) {
    // IKM, digest and out are mandatory and validated by the bridge.
    // salt and info are optional: a NULL salt means "use HashLen zeros"
    // (RFC 5869), a NULL/empty info means "no context info".
    jo_assert(ikm != NULL);
    jo_assert(digest != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "HKDF", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(3002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);

    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(3000);
        goto exit;
    }

    // Hard-code the HKDF mode to RFC 5869 extract-and-expand. This is the
    // EVP_KDF "HKDF" default, but set it explicitly so the one-shot semantics
    // the consumers rely on survive a default change or a custom provider.
    // DO NOT change this value.
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

    OSSL_PARAM params[6];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
    // Uniform guards: a zero-length salt/info is deliberately treated the same
    // as an absent one. For the salt the two forms are RFC-equivalent anyway —
    // an empty HMAC key is padded to HashLen zeros, which is exactly the
    // RFC 5869 default-salt behaviour the omitted param produces.
    if (salt != NULL && salt_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    }
    if (info != NULL && info_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len);
    }
    params[idx++] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(3001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}


/*
 * SP 800-108 KBKDF. mode is "COUNTER" or "FEEDBACK"; mac is "HMAC" (with
 * digest) or "CMAC" (with cipher). label and context are optional - measured
 * on all four supported environments, an absent one is byte-identical to an
 * empty one, so the zero-length form is folded into the absent form here
 * exactly as jo_hkdf folds salt and info.
 *
 * use_l and use_separator are passed through as the caller gave them and are
 * NOT defaulted here. OpenSSL defaults both to 1 (the SP 800-108 fixed-input
 * form, Label || 0x00 || Context || [L]); BouncyCastle's
 * KDFCounterBytesGenerator and the NIST CAVP vectors both use the raw form
 * with neither. Both are legitimate and the difference is invisible in a
 * round trip, so the choice belongs to the caller and is always explicit.
 *
 * No bound is placed on key_len. The SP 800-131A 112-bit floor is enforced by
 * the FIPS module when kbkdf-key-check is configured and NOT otherwise
 * (measured: 1 byte is accepted on mainline and on FIPS 3.1.2, refused below
 * 14 under -pedantic). A pre-check here would be wrong on whichever module it
 * did not match - see the classify-don't-pre-check rule in native-code.md.
 */
int32_t jo_kbkdf(
    uint8_t *mode, size_t mode_len,
    uint8_t *mac, size_t mac_len,
    uint8_t *digest, size_t digest_len,
    uint8_t *cipher, size_t cipher_len,
    uint8_t *key, size_t key_len,
    uint8_t *label, size_t label_len,
    uint8_t *context, size_t context_len,
    uint8_t *seed, size_t seed_len,
    int32_t r,
    int32_t use_l,
    int32_t use_separator,
    uint8_t *out, size_t out_len
) {
    // mode, mac, key and out are mandatory and validated by the bridge; at
    // least one of digest/cipher is present, also checked by the bridge.
    // label, context and seed are optional.
    jo_assert(mode != NULL);
    jo_assert(mac != NULL);
    jo_assert(key != NULL);
    jo_assert(out != NULL);
    jo_assert(digest != NULL || cipher != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "KBKDF", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(4002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(4000);
        goto exit;
    }

    OSSL_PARAM params[12];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, (char *) mode, mode_len);
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, (char *) mac, mac_len);
    if (digest != NULL) {
        params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    }
    if (cipher != NULL) {
        params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, (char *) cipher, cipher_len);
    }
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, key_len);
    // OSSL_KDF_PARAM_SALT is SP 800-108's Label; OSSL_KDF_PARAM_INFO is its
    // Context. "label" and "context" are NOT settable names - set_params would
    // have ignored either silently while returning 1.
    if (label != NULL && label_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, label, label_len);
    }
    if (context != NULL && context_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, context, context_len);
    }
    // The feedback IV, K(0). OpenSSL spells it "seed"; SP 800-108 and
    // BouncyCastle both call it the IV. Meaningless in counter mode, where
    // OpenSSL ignores it, so it is simply omitted when absent.
    if (seed != NULL && seed_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, seed, seed_len);
    }
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_R, &r);
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_L, &use_l);
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, &use_separator);
    params[idx++] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(4001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}


/*
 * SP 800-56C one-step KDF over a digest (the "SSKDF" EVP_KDF).
 *
 * No salt parameter is exposed. OSSL_KDF_PARAM_SALT is settable on the ctx but
 * was measured to be SILENTLY IGNORED in digest mode on all four supported
 * environments - varying it produces the identical key. It is live only for
 * the MAC-based variants, which this entry point does not serve. Exposing a
 * knob that does nothing is the footgun; leaving it out is the fix.
 *
 * As with jo_kbkdf, no bound is placed on secret_len: the 112-bit floor is
 * sskdf-key-check's, present on one supported module and absent on the other.
 */
int32_t jo_sskdf(
    uint8_t *digest, size_t digest_len,
    uint8_t *secret, size_t secret_len,
    uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len
) {
    // digest, secret and out are mandatory and validated by the bridge;
    // info is optional (absent == empty, measured).
    jo_assert(digest != NULL);
    jo_assert(secret != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "SSKDF", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(5002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(5000);
        goto exit;
    }

    OSSL_PARAM params[4];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, secret, secret_len);
    if (info != NULL && info_len > 0) {
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len);
    }
    params[idx++] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(5001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}


/*
 * RFC 4253 section 7.2 SSH key derivation.
 *
 * Every input is mandatory: unlike a salt or an info string, the exchange hash
 * H and the session id have no defined "absent" form. type is a single letter
 * A..F selecting which of the six keys is produced; a letter outside that set
 * is left to OpenSSL, which refuses it with "value error" on all four measured
 * environments.
 *
 * out_len of 0 is refused by the BRIDGE, not here: SSHKDF is the one KDF of
 * the three that accepts a zero-length request and cheerfully emits a
 * zero-length key on every environment measured.
 */
int32_t jo_sshkdf(
    uint8_t *digest, size_t digest_len,
    uint8_t *key, size_t key_len,
    uint8_t *xcghash, size_t xcghash_len,
    uint8_t *session_id, size_t session_id_len,
    uint8_t *type, size_t type_len,
    uint8_t *out, size_t out_len
) {
    jo_assert(digest != NULL);
    jo_assert(key != NULL);
    jo_assert(xcghash != NULL);
    jo_assert(session_id != NULL);
    jo_assert(type != NULL);
    jo_assert(out != NULL);

    int ret = JO_FAIL;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;

    ERR_clear_error();

    kdf = EVP_KDF_fetch(get_global_jostle_ossl_lib_ctx(), "SSHKDF", NULL);
    if (OPS_OPENSSL_ERROR_1 kdf == NULL) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_1(6002);
        goto exit;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (OPS_OPENSSL_ERROR_2 !kctx) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_2(6000);
        goto exit;
    }

    OSSL_PARAM params[6];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) digest, digest_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key, key_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH, xcghash, xcghash_len);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID, session_id,
                                                      session_id_len);
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE, (char *) type, type_len);
    params[idx++] = OSSL_PARAM_construct_end();

    if (OPS_OPENSSL_ERROR_3 EVP_KDF_derive(kctx, out, out_len, params) <= 0) {
        ret = JO_OPENSSL_ERROR OPS_OFFSET_OPENSSL_ERROR_3(6001);
        goto exit;
    }

    ret = JO_SUCCESS;
exit:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

