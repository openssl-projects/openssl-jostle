/*
 *  Copyright 2025 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider;

public interface OpenSSLNI
{
    int setOSSLProviderModule(String provider);

    String getOSSLErrors();

    // ------------------------------------------------------------------
    // Capability probe
    //
    // JSL links whatever mainline libcrypto it was built against, and not
    // every supported one serves every family JSL knows how to drive — the
    // PQC families need 3.5 or later. This is the MECHANISM; the policy
    // lives in Capabilities.
    //
    // The values are the C contract (JO_CAP_OP_* in util/capability.h) and
    // are shared with OpenSSLFIPSNI, whose constants alias these rather than
    // restating them.
    // ------------------------------------------------------------------

    /** {@link #canFetch} operation type: EVP_KEYMGMT_fetch. */
    int OP_KEYMGMT = 1;
    /** {@link #canFetch} operation type: EVP_KEYEXCH_fetch. */
    int OP_KEYEXCH = 2;
    /** {@link #canFetch} operation type: EVP_SIGNATURE_fetch. */
    int OP_SIGNATURE = 3;
    /** {@link #canFetch} operation type: EVP_ASYM_CIPHER_fetch. */
    int OP_ASYM_CIPHER = 4;
    /** {@link #canFetch} operation type: EVP_MD_fetch. */
    int OP_MD = 5;
    /** {@link #canFetch} operation type: EVP_CIPHER_fetch. */
    int OP_CIPHER = 6;
    /** {@link #canFetch} operation type: EVP_KDF_fetch. */
    int OP_KDF = 7;
    /** {@link #canFetch} operation type: EVP_MAC_fetch. */
    int OP_MAC = 8;
    /** {@link #canFetch} operation type: EVP_RAND_fetch. */
    int OP_RAND = 9;

    /**
     * Can the linked libcrypto resolve {@code name} for {@code opType} in the
     * base lib ctx?
     *
     * <p>A fetch and an immediate free, with the error queue scrubbed
     * afterwards so a negative answer leaves no trace for an unrelated call
     * to report. It answers only "is this name resolvable" — a capability
     * that a real operation reveals but a fetch does not is NOT detectable
     * here and must be classified where it fails.
     *
     * @param opType one of the {@code OP_*} constants.
     * @param name   algorithm name to resolve.
     * @return 1 when the fetch succeeds, 0 when it does not, or a negative
     * JO_* code when the arguments are unusable ({@code JO_NAME_IS_NULL},
     * {@code JO_UNEXPECTED_STATE} for an unknown {@code opType}).
     */
    int canFetch(int opType, String name);
}
