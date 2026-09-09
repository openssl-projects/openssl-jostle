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
 * Every one of these is refused rather than ignored. Ignoring returns a green
 * result for a check that never ran, and revocation is the case that matters:
 * {@code isRevocationEnabled()} defaults to TRUE, so silently dropping it would
 * tell a caller who never opted out that a path is good when its revocation
 * status was never looked at.
 */
final class CertPathParams
{
    private CertPathParams()
    {
    }

    static void refuseUnsupported(PKIXParameters pkix) throws InvalidAlgorithmParameterException
    {
        if (pkix.isRevocationEnabled())
        {
            throw new InvalidAlgorithmParameterException(
                    "revocation checking is not implemented yet; call "
                            + "setRevocationEnabled(false) to validate without it");
        }
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
                throw new InvalidAlgorithmParameterException(
                        "a TrustAnchor with name constraints is not supported yet: this phase "
                                + "cannot apply them, and ignoring them would validate a path "
                                + "the constraints were meant to exclude");
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
