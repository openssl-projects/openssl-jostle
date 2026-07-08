//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef XEC_H
#define XEC_H
#include <stdint.h>

#include "key_spec.h"


// =============================================================
// Key generation (X25519 / X448)
// =============================================================

/*
 * Generate an X25519 or X448 keypair. The resulting EVP_PKEY is written
 * into spec->key. Returns JO_SUCCESS on success or a negative error code
 * on failure; on failure spec->key is left NULL.
 *
 *   name:    the OpenSSL key-type name, "X25519" or "X448". MUST be
 *            non-NULL. Unlike EC there is no curve/group parameter — for
 *            these Montgomery key types the type name fully determines the
 *            key. An unrecognised name produces JO_OPENSSL_ERROR.
 *   rnd_src: RandSource for keygen entropy. MUST be non-NULL.
 *
 * Key agreement (the ECDH-style EVP_PKEY_derive flow) is provided by the
 * type-agnostic ec_kex_* functions in ec.c, which accept X25519 / X448
 * keys via check_is_ec_or_xec. XEC adds only key generation.
 */
int32_t xec_generate_key(key_spec *spec, const char *name, void *rnd_src);


#endif // XEC_H
