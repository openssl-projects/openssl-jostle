//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef CAPABILITY_H
#define CAPABILITY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Can this library's lib ctx resolve an algorithm name?
 *
 * Both trees need the question and the mechanism is the same, so this file is
 * an ordinary twin. Only the reason differs:
 *
 *   FIPS  — JSLFIPS ships one build for two modules that disagree about what
 *           they implement, so its registered surface must be decided from
 *           whichever module is loaded.
 *   base  — JSL links whatever mainline libcrypto it was built against, and
 *           the PQC families need 3.5 or later. Registering them against an
 *           older libcrypto resolves through getInstance and then fails at
 *           first use.
 *
 * This file is the MECHANISM; the policy — which capability gates which
 * registration — lives in Java, in Capabilities / FIPSCapabilities.
 *
 * Deliberately narrow. Probing exists only for capabilities that legitimately
 * differ between supported builds, and only where a cheap, side-effect-free
 * question can answer them. A capability that only the real operation reveals
 * — DSA key generation, PKCS#1 v1.5 encrypt — is NOT probeable here and is
 * classified where it fails instead (see classify_dsa_gen_failure in dsa.c).
 *
 * The FIPS tree carries two further probes in capability_fips.h; both are
 * meaningless in the base lib ctx, which is why they are not here.
 */

/*
 * Operation types for capability_can_fetch. Values are part of the NI
 * contract — they must match the OP_* constants on OpenSSLNI and
 * OpenSSLFIPSNI.
 */
#define JO_CAP_OP_KEYMGMT 1
#define JO_CAP_OP_KEYEXCH 2
#define JO_CAP_OP_SIGNATURE 3
#define JO_CAP_OP_ASYM_CIPHER 4
#define JO_CAP_OP_MD 5
#define JO_CAP_OP_CIPHER 6
#define JO_CAP_OP_KDF 7
#define JO_CAP_OP_MAC 8
#define JO_CAP_OP_RAND 9

/* Inclusive bounds the bridges range-check op_type against. */
#define JO_CAP_OP_MIN JO_CAP_OP_KEYMGMT
#define JO_CAP_OP_MAX JO_CAP_OP_RAND

/**
 * Can this library's lib ctx resolve name for op_type under its default
 * properties (fips=yes in the FIPS tree, none in the base tree)?
 *
 * Fetches and immediately frees, then scrubs the error queue so a negative
 * answer leaves nothing behind for an unrelated call to report.
 *
 * Preconditions asserted as invariants (both bridges enforce them):
 * name != NULL, and JO_CAP_OP_MIN <= op_type <= JO_CAP_OP_MAX.
 *
 * @return 1 when the fetch succeeds, 0 when it does not.
 */
int32_t capability_can_fetch(int32_t op_type, const char *name);

#endif //CAPABILITY_H
