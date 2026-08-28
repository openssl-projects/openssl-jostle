/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

/**
 * What the mainline libcrypto JSL was built against can actually do.
 *
 * <p>JSL links whatever libcrypto the distributor supplied, and the PQC
 * families need OpenSSL 3.5 or later. Registered unconditionally they resolve
 * through {@code getInstance} and then fail at first use — the
 * "registration is not usability" trap the FIPS side already avoids.
 * {@code NoSuchAlgorithmException} is the cleaner contract, and it lets the
 * caller fall through to another provider.
 *
 * <p>Scope, as for {@code FIPSCapabilities}: probe only what legitimately
 * differs between supported builds, and only where a cheap side-effect-free
 * question answers it. A capability that only the real operation reveals is
 * classified where it fails, in C. This is <b>capability</b> filtering, never
 * <b>approval</b> filtering.
 *
 * <p>Currently: ML-KEM, ML-DSA, SLH-DSA and the four TLS hybrid groups.
 * Measured 2026-08-28 by {@code fips-c-review/probes/base_pqc_gate_probe.c} —
 * every one of those names fetches on the project's build target (3.5.8) and
 * on 3.6.2, so on either the gate is all-true and its absent arm does not
 * execute. It exists for the older libcrypto a distributor may link, and no
 * available configuration exercises it; see {@code BaseCapabilityGateTest},
 * which says so rather than leaving it to be discovered.
 */
final class Capabilities
{
    private Capabilities()
    {
    }

    /**
     * Whether the linked libcrypto resolves {@code name} as a key-management
     * algorithm.
     *
     * <p>Any answer other than a definite "no" registers. A probe that fails
     * for its own reasons (a negative JO_* code) must not silently drop a
     * service — register, and let the operation fail typed if it truly cannot
     * run.
     */
    static boolean canFetchKeyMgmt(String name)
    {
        return NISelector.OpenSSLNI.canFetch(OpenSSLNI.OP_KEYMGMT, name) != 0;
    }
}
