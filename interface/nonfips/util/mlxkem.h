//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE

#ifndef MLXKEM_H
#define MLXKEM_H

#include <stdint.h>
#include <stddef.h>
#include "key_spec.h"

/*
 * The four TLS hybrid KEMs (draft-ietf-tls-ecdhe-mlkem): X25519MLKEM768,
 * X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024.
 *
 * Encapsulation and decapsulation are NOT here - they go through the generic
 * encap/decap in encapdecap.c, which drives EVP_PKEY_CTX_new_from_pkey and
 * cares nothing for the algorithm. Hybrids need no kem-op name either, unlike
 * RSASVE. What this file adds is keygen and the key-material accessors, which
 * cannot reuse the ML-KEM ones:
 *
 *   1. The public half is OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, the TLS wire
 *      share. OSSL_PKEY_PARAM_PUB_KEY is NOT gettable on any variant, so the
 *      ML-KEM getter would fail at runtime on all four.
 *   2. There is NO ASN.1 codec - providers/encoders.inc and decoders.inc carry
 *      21 and 6 entries for pure ML-KEM and zero for any hybrid, and
 *      i2d_PUBKEY / i2d_PrivateKey return -1. Reconstruction is by
 *      EVP_PKEY_fromdata instead, which the keymgmt's imexport_types does
 *      advertise for PUB_KEY and PRIV_KEY.
 *   3. Importing a public key uses PUB_KEY even though EXPORTING one does not.
 *      That asymmetry is measured, not assumed.
 *
 * Measured: fips-c-review/probes/hybrid_kem_probe.c, against mainline 3.6.2
 * and FIPS 3.5.7 / 3.5.8.
 */

/* Keygen. No seed parameter - hybrids have no ML_KEM_SEED equivalent. */
int32_t mlxkem_generate_key_pair(key_spec *spec, int32_t type, void *rnd_src);

/*
 * The public wire share. Pass out == NULL to learn the length.
 */
int32_t mlxkem_get_public_encoded(key_spec *spec, uint8_t *out, size_t out_len);

/*
 * The raw private half. Pass out == NULL to learn the length.
 *
 * Returns JO_HYBRID_PRIVATE_EXPORT_UNSUPPORTED for the SecP variants, whose
 * size query answers and whose fetch then refuses without raising. That
 * refusal is detected by attempting the fetch, never by naming the variant -
 * a version that starts supporting it must start working, not stay refused.
 */
int32_t mlxkem_get_private_encoded(key_spec *spec, uint8_t *out, size_t out_len);

/* Rebuild a public-only key from its wire share. */
int32_t mlxkem_decode_public_key(key_spec *spec, int32_t type, uint8_t *src, size_t src_len);

/* Rebuild a keypair from the raw private half. */
int32_t mlxkem_decode_private_key(key_spec *spec, int32_t type, uint8_t *src, size_t src_len);

#endif //MLXKEM_H
