//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
//
//  X25519 / X448 key generation. The actual ECDH-style key agreement
//  (init / set_peer / derive) is provided by the type-agnostic
//  `ec_kex_*` functions in ec.c — those operate on an EVP_PKEY_CTX
//  built via EVP_PKEY_CTX_new_from_pkey and don't care whether the
//  underlying EVP_PKEY is EC or one of the Montgomery curves.

#ifndef XEC_H
#define XEC_H
#include <stddef.h>
#include <stdint.h>

#include "key_spec.h"

/**
 * Generate a new X25519 or X448 keypair into `spec`.
 *
 * `curve_name` is the OpenSSL provider name of the key type, currently
 * one of "X25519" or "X448". The function returns
 * {@code JO_CURVE_NOT_SUPPORTED} if OpenSSL doesn't recognise the name.
 */
int32_t xec_generate_key(key_spec *spec, const char *curve_name,
                         void *rnd_src);

/**
 * Quick predicate: does OpenSSL recognise `curve_name` as a valid
 * X25519 / X448 type? Returns 1 (supported) or {@code JO_CURVE_NOT_SUPPORTED}.
 * Mirrors {@code ec_curve_supported} but probes via EVP_PKEY_CTX_new_from_name
 * since the Montgomery curves aren't reachable through the named-group
 * mechanism EC uses.
 */
int32_t xec_curve_supported(const char *curve_name);

#endif // XEC_H
