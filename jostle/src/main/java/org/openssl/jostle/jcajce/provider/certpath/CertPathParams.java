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

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;

/**
 * Refuses the PKIX parameters this phase cannot honour.
 * <p>
 * Every one of these is refused rather than ignored, because ignoring returns
 * a green result for a check that never ran.
 * <p>
 * Revocation is no longer among them — CRL checking is honoured over the whole
 * path. What still keeps OCSP and a caller-driven revocation policy out is the
 * {@code PKIXCertPathChecker} refusal below, which is what
 * {@code PKIXRevocationChecker} arrives as.
 */
final class CertPathParams
{
    private CertPathParams()
    {
    }

    static void refuseUnsupported(PKIXParameters pkix) throws InvalidAlgorithmParameterException
    {
        if (pkix.isExplicitPolicyRequired())
        {
            throw new InvalidAlgorithmParameterException(
                    "explicit policy is not supported: this provider does no policy processing");
        }
        if (pkix.isPolicyMappingInhibited())
        {
            throw new InvalidAlgorithmParameterException(
                    "policy mapping inhibition is not supported: this provider does no policy processing");
        }
        if (pkix.isAnyPolicyInhibited())
        {
            throw new InvalidAlgorithmParameterException(
                    "any-policy inhibition is not supported: this provider does no policy processing");
        }
        if (pkix.getInitialPolicies() != null && !pkix.getInitialPolicies().isEmpty())
        {
            throw new InvalidAlgorithmParameterException(
                    "an initial policy set is not supported: this provider does no policy processing");
        }
        if (pkix.getCertPathCheckers() != null && !pkix.getCertPathCheckers().isEmpty())
        {
            throw new InvalidAlgorithmParameterException(
                    "PKIXCertPathChecker is not supported yet");
        }
        if (pkix.getTrustAnchors().isEmpty())
        {
            throw new InvalidAlgorithmParameterException("no trust anchors supplied");
        }
        for (TrustAnchor anchor : pkix.getTrustAnchors())
        {
            if (anchor.getNameConstraints() != null)
            {
                // OpenSSL DOES apply an anchor certificate's own name
                // constraints (x509_vfy.c check_name_constraints, 3.1.2 :646,
                // 3.5.8 :776), so only the separate-BYTES form is refused —
                // that one has no X509_VERIFY_PARAM setter.
                throw new InvalidAlgorithmParameterException(
                        "a TrustAnchor carrying name-constraint bytes beside its certificate is "
                                + "not supported: OpenSSL applies the constraints IN an anchor "
                                + "certificate, but has no way to take them separately, and "
                                + "ignoring them would validate a path they were meant to exclude");
            }
            if (anchor.getTrustedCert() == null)
            {
                throw new InvalidAlgorithmParameterException(
                        "a TrustAnchor must carry a certificate: this provider validates through "
                                + "OpenSSL's X509_STORE, which holds certificates rather than a "
                                + "name and key");
            }
        }
    }
}
