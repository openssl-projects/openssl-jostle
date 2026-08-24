//  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef KDF_H
#define KDF_H
#include <stddef.h>
#include <stdint.h>


int32_t jo_pbkdf2(
    uint8_t *password, size_t password_len,
    uint8_t *salt, size_t salt_len,
    uint32_t iter,
    uint8_t *digest,
    size_t digest_len,
    uint8_t *out,
    size_t out_len
);

int32_t jo_hkdf(
    uint8_t *ikm, size_t ikm_len,
    uint8_t *salt, size_t salt_len,
    uint8_t *info, size_t info_len,
    uint8_t *digest, size_t digest_len,
    uint8_t *out, size_t out_len
);

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
);

int32_t jo_sskdf(
    uint8_t *digest, size_t digest_len,
    uint8_t *secret, size_t secret_len,
    uint8_t *info, size_t info_len,
    uint8_t *out, size_t out_len
);

int32_t jo_sshkdf(
    uint8_t *digest, size_t digest_len,
    uint8_t *key, size_t key_len,
    uint8_t *xcghash, size_t xcghash_len,
    uint8_t *session_id, size_t session_id_len,
    uint8_t *type, size_t type_len,
    uint8_t *out, size_t out_len
);

#endif //KDF_H
