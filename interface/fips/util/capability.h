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
 * Capability probes for the loaded FIPS module.
 *
 * JSLFIPS serves ONE build against two modules that disagree about what they
 * implement — the CMVP-validated 3.1.2 and a 3.5.x once certified — so the
 * registered surface has to be decided from whichever module is actually
 * loaded rather than from a compiled-in list. This file is the MECHANISM;
 * the policy (which capability gates which registration) lives in Java.
 *
 * Deliberately narrow. Probing exists only for capabilities that legitimately
 * differ between supported modules, and only where a cheap, side-effect-free
 * question can answer them. A capability that only the real operation reveals
 * — DSA key generation, PKCS#1 v1.5 encrypt — is NOT probeable here and is
 * classified where it fails instead (see classify_dsa_gen_failure in dsa.c).
 *
 * FIPS-tree only: the base provider links one mainline libcrypto whose
 * surface is fixed at build time, so it has nothing to probe.
 */

/*
 * Operation types for capability_can_fetch. Values are part of the NI
 * contract — they must match the OP_* constants on OpenSSLFIPSNI.
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
 * Can the loaded module resolve name for op_type under this library's lib ctx
 * (which is pinned to fips=yes default properties)?
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

/**
 * Write the loaded FIPS provider's "<name> <version>" into out, NUL
 * terminated and truncated to fit.
 *
 * Diagnostics only. A gate keyed on a version string is the transcribed
 * table the project rules forbid, and it is wrong on its own terms: the
 * version names the build, not the capability.
 *
 * Precondition asserted as an invariant: out != NULL && out_len > 0.
 *
 * @return the number of bytes written excluding the terminator, or a
 * negative JO_* code when the provider cannot be queried.
 */
int32_t capability_module_version(char *out, size_t out_len);

#endif //CAPABILITY_H
