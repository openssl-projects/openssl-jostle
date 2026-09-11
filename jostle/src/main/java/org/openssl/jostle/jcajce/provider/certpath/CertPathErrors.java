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

/**
 * Maps an {@code X509_V_*} code to the JCE exception a caller reacts to.
 *
 * <p>The JDK has one message, "Could not determine revocation status", for
 * every CRL fault, so our per-cause texts cannot be pinned against it — the
 * REASON is pinned against the JDK, the MESSAGES against themselves.
 */
final class CertPathErrors
{
    /* X509_V_* codes this provider maps to a BasicReason; others are UNSPECIFIED. */
    private static final int ERR_CERT_NOT_YET_VALID = 9;
    private static final int ERR_CERT_HAS_EXPIRED = 10;
    private static final int ERR_CERT_SIGNATURE_FAILURE = 7;
    private static final int ERR_CERT_REVOKED = 23;

    /* The CRL faults, all UNDETERMINED_REVOCATION_STATUS, each with its own text. */
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

    static CertPathValidatorException toValidatorException(int error, int depth, CertPath path)
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
            case ERR_UNABLE_TO_GET_CRL:
            case ERR_CRL_SIGNATURE_FAILURE:
            case ERR_CRL_NOT_YET_VALID:
            case ERR_CRL_HAS_EXPIRED:
            case ERR_UNABLE_TO_GET_CRL_ISSUER:
            case ERR_DIFFERENT_CRL_SCOPE:
            case ERR_CRL_PATH_VALIDATION_ERROR:
            case ERR_KEYUSAGE_NO_CRL_SIGN:
            // The JDK is not self-consistent on code 36 — UNSPECIFIED for
            // PKITS 4.4.8, UNDETERMINED for 4.4.9 and 4.4.10 — so 4.4.8 is
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
                "certification path validation failed: " + error + " " + describe(error),
                null, path, index, reason);
    }

    /**
     * A short name for the code. Deliberately NOT OpenSSL's own string: that
     * would need another native call on the failure path, and these are the
     * only codes this phase can produce a reason for.
     */
    private static String describe(int error)
    {
        switch (error)
        {
            case ERR_UNABLE_TO_GET_CRL:      return "no CRL was supplied for an issuer in the path";
            case ERR_CERT_SIGNATURE_FAILURE: return "certificate signature failure";
            case ERR_CRL_SIGNATURE_FAILURE:  return "CRL signature failure";
            case ERR_CERT_NOT_YET_VALID:     return "certificate is not yet valid";
            case ERR_CERT_HAS_EXPIRED:       return "certificate has expired";
            case ERR_CRL_NOT_YET_VALID:      return "CRL is not yet valid";
            case ERR_CRL_HAS_EXPIRED:        return "CRL has expired";
            case 20:                         return "unable to get local issuer certificate";
            case ERR_CERT_REVOKED:           return "certificate revoked";
            case 24:                         return "invalid CA certificate";
            case 25:                         return "path length constraint exceeded";
            case 26:                         return "unsupported certificate purpose";
            case ERR_KEYUSAGE_NO_CRL_SIGN:   return "the CRL signer's keyUsage does not allow cRLSign";
            case ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
                                             return "the CRL carries a critical extension this provider cannot process";
            case ERR_UNABLE_TO_GET_CRL_ISSUER:
                                             return "the CRL issuer certificate could not be found";
            case ERR_DIFFERENT_CRL_SCOPE:    return "the CRL does not cover the certificate's scope";
            case ERR_CRL_PATH_VALIDATION_ERROR:
                                             return "the CRL issuer's own certification path did not validate";
            case 89:                         return "basic constraints of CA cert not marked critical";
            default:                         return "X509_V error";
        }
    }
}
