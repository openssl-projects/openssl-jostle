/*
 *
 *   Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *   Licensed under the Apache License 2.0 (the "License"). You may not use
 *   this file except in compliance with the License.  You can obtain a copy
 *   in the file LICENSE in the source distribution or at
 *   https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.jcajce.provider.certpath;

import org.openssl.jostle.jcajce.provider.DefaultServiceNI;

/**
 * Certification path validation over OpenSSL's {@code X509_verify_cert}.
 * <p>
 * One entry point: every certificate crosses in one concatenated DER buffer
 * with a lengths array — anchors first, then untrusted, then the target last,
 * and the CRLs after all of them, so {@code sizes} carries
 * {@code count + crlCount} entries. The built chain comes back in a
 * caller-supplied buffer, which is safe to size as the input's length because
 * the chain can only be a subset of the certificates supplied.
 */
public interface CertPathNI
    extends DefaultServiceNI
{
    /** Fixed leading entries of {@code outInfo}: error, depth, chain count. */
    int OUT_INFO_HEADER = 3;

    /**
     * Validate at the current time. NOT zero: the epoch is a legitimate
     * {@code Date}, and a sentinel a caller can supply by accident is a bug
     * waiting for one. Matches {@code CERTPATH_TIME_NOW} in certpath.h.
     */
    long TIME_NOW = Long.MIN_VALUE;

    /** {@code policyFlags} bits, matching {@code CERTPATH_POLICY_*} in certpath.h. */
    int POLICY_NONE = 0;
    int POLICY_EXPLICIT = 1;
    int POLICY_INHIBIT_ANY = 2;
    int POLICY_INHIBIT_MAP = 4;

    /**
     * @param der         concatenated DER: anchors, untrusted, target, CRLs
     * @param sizes       one length per entry, {@code count + crlCount} of them
     * @param count       how many entries are certificates
     * @param crlCount    how many trailing entries are CRLs; may be 0
     * @param anchorCount how many leading entries are trust anchors
     * @param timeSecs    validation time in seconds since the epoch, or {@link #TIME_NOW}
     * @param strict      non-zero adds {@code X509_V_FLAG_X509_STRICT}
     * @param revocation  non-zero turns CRL checking on for the WHOLE path
     * @param policyFlags {@code POLICY_*} bits; policy processing itself is always on
     * @param policies    {@code policyCount} DER OBJECT IDENTIFIER TLVs, concatenated:
     *                    the initial policy set; may be null when the count is 0
     * @param policyCount how many initial policies; 0 means any policy
     * @param chainOut    receives the built chain's concatenated DER
     * @param outInfo     {@code [error, depth, chainCount, size0 … sizeN-1]},
     *                    so at least {@code OUT_INFO_HEADER + count} entries;
     *                    written on success and on a certificate or CRL decode
     *                    failure ({@code [code, index, 0]}), untouched otherwise
     * @param treeOut     at least one entry; element 0 receives the policy tree
     *                    after a successful validation, in certpath.h's
     *                    CERTPATH_TREE layout, and is untouched when there is none
     * @return {@code JO_SUCCESS} when the verification RAN — its verdict is
     *         {@code outInfo[0]}, an {@code X509_V_*} code — or a negative
     *         {@code JO_*} when it could not be attempted
     */
    int ni_verify(byte[] der, int[] sizes, int count, int crlCount, int anchorCount,
                  long timeSecs, int strict, int revocation,
                  int policyFlags, byte[] policies, int policyCount,
                  byte[] chainOut, int[] outInfo, byte[][] treeOut);

    /**
     * OpenSSL's own text for an {@code X509_V_*} code, from the linked library.
     *
     * @param error the code {@code outInfo[0]} reported
     * @return the text, never null
     */
    String ni_errorText(int error);
}
