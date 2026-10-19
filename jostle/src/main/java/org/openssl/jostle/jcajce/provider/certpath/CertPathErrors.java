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

import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.PKIXReason;

/**
 * Maps an {@code X509_V_*} code to the JCE exception a caller reacts to.
 *
 * <p>The REASON is a JCA enum, so the code-to-reason map is ours; the TEXT is
 * OpenSSL's own, asked of the linked library, so no row of it can drift.
 */
final class CertPathErrors
{
    /* X509_V_* codes this provider maps to a reason; others are UNSPECIFIED. */
    private static final int ERR_CERT_NOT_YET_VALID = 9;
    private static final int ERR_CERT_HAS_EXPIRED = 10;
    private static final int ERR_CERT_SIGNATURE_FAILURE = 7;
    private static final int ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
    private static final int ERR_CERT_REVOKED = 23;
    private static final int ERR_INVALID_CA = 79;

    /* The CRL faults, all UNDETERMINED_REVOCATION_STATUS. */
    private static final int ERR_UNABLE_TO_GET_CRL = 3;
    private static final int ERR_CRL_SIGNATURE_FAILURE = 8;
    private static final int ERR_CRL_NOT_YET_VALID = 11;
    private static final int ERR_CRL_HAS_EXPIRED = 12;
    private static final int ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
    private static final int ERR_DIFFERENT_CRL_SCOPE = 44;
    private static final int ERR_CRL_PATH_VALIDATION_ERROR = 54;
    private static final int ERR_KEYUSAGE_NO_CRL_SIGN = 35;
    private static final int ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;

    private CertPathErrors()
    {
    }

    static CertPathValidatorException toValidatorException(CertPathNI ni, int error, int depth, CertPath path)
    {
        CertPathValidatorException.Reason reason;
        switch (error)
        {
            case ERR_CERT_HAS_EXPIRED:
                reason = CertPathValidatorException.BasicReason.EXPIRED;
                break;
            case ERR_CERT_NOT_YET_VALID:
                reason = CertPathValidatorException.BasicReason.NOT_YET_VALID;
                break;
            case ERR_CERT_SIGNATURE_FAILURE:
                reason = CertPathValidatorException.BasicReason.INVALID_SIGNATURE;
                break;
            case ERR_CERT_REVOKED:
                reason = CertPathValidatorException.BasicReason.REVOKED;
                break;
            case ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
                // No supplied anchor issues the chain: the JDK's reason for the same path.
                reason = PKIXReason.NO_TRUST_ANCHOR;
                break;
            case ERR_INVALID_CA:
                reason = CertPathValidatorException.BasicReason.UNSPECIFIED;
                break;
            case ERR_UNABLE_TO_GET_CRL:
            case ERR_CRL_SIGNATURE_FAILURE:
            case ERR_CRL_NOT_YET_VALID:
            case ERR_CRL_HAS_EXPIRED:
            case ERR_UNABLE_TO_GET_CRL_ISSUER:
            case ERR_DIFFERENT_CRL_SCOPE:
            case ERR_CRL_PATH_VALIDATION_ERROR:
            case ERR_KEYUSAGE_NO_CRL_SIGN:
            // The JDK is not self-consistent on code 36: UNSPECIFIED for
            // PKITS 4.4.8, UNDETERMINED for 4.4.9 and 4.4.10, so 4.4.8 is
            // pinned as a divergence rather than matched.
            case ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
                // An expired CRL arrives as 11 or 12, so it is undetermined
                // status rather than a revoked certificate.
                reason = CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS;
                break;
            default:
                reason = CertPathValidatorException.BasicReason.UNSPECIFIED;
                break;
        }

        // OpenSSL counts depth from the target; so does CertPath. A depth past
        // the path's end is the anchor, which CertPath does not contain, and
        // the JCE contract wants -1 there rather than an out-of-range index.
        int index = depth;
        if (path == null || index < 0 || index >= path.getCertificates().size())
        {
            index = -1;
        }
        return new CertPathValidatorException(
                "certification path validation failed: " + error + " " + ni.ni_errorText(error),
                null, path, index, reason);
    }
}
