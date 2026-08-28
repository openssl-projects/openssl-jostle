//  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
//
//  Licensed under the Apache License 2.0 (the "License"). You may not use
//  this file except in compliance with the License.  You can obtain a copy
//  in the file LICENSE in the source distribution or at
//  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE


#ifndef CAPABILITY_FIPS_H
#define CAPABILITY_FIPS_H

#include <stddef.h>
#include <stdint.h>

#include "capability.h"

/*
 * The two capability probes that only make sense against a loaded FIPS
 * module. Kept apart from capability.h so the shared fetch probe stays a
 * byte-identical twin across the two trees: the base lib ctx hosts no "fips"
 * provider, so capability_module_version has nothing to load, and
 * capability_implementing_provider would only ever answer "default".
 */

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

/**
 * Name the OSSL_PROVIDER that actually IMPLEMENTS name for op_type in this
 * library's lib ctx - "fips" for the FIPS module, "default" for mainline's
 * built-in provider.
 *
 * This is the only direct evidence that an operation runs inside the module.
 * Every other signal is indirect: absence tests (Triple-DES, ChaCha20) show
 * the lib ctx carries fips=yes properties, and behavioural refusals (q-less
 * DH, SHA-1 signing) show the module is in the path for THOSE algorithms. For
 * a family mainline implements identically - all three PQC families do - there
 * is no behavioural difference to observe, so nothing else can distinguish
 * "ran in the module" from "ran in mainline's default provider".
 *
 * Preconditions asserted as invariants (both bridges enforce them):
 * name != NULL, out != NULL, out_len > 0, and
 * JO_CAP_OP_MIN <= op_type <= JO_CAP_OP_MAX.
 *
 * @return bytes written excluding the terminator, or JO_NAME_NOT_FOUND when
 * the algorithm is not fetchable at all.
 */
int32_t capability_implementing_provider(int32_t op_type, const char *name,
                                         char *out, size_t out_len);

#endif //CAPABILITY_FIPS_H
