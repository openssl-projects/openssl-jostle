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

/** Maps an {@code X509_V_*} code to the JCE exception a caller reacts to. */
final class CertPathErrors
{
    /* X509_V_* codes this provider maps to a BasicReason; others are UNSPECIFIED. */
    private static final int ERR_CERT_NOT_YET_VALID = 9;
    private static final int ERR_CERT_HAS_EXPIRED = 10;
    private static final int ERR_CERT_SIGNATURE_FAILURE = 7;
    private static final int ERR_CERT_REVOKED = 23;

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
            case ERR_CERT_SIGNATURE_FAILURE: return "certificate signature failure";
            case ERR_CERT_NOT_YET_VALID:     return "certificate is not yet valid";
            case ERR_CERT_HAS_EXPIRED:       return "certificate has expired";
            case 20:                         return "unable to get local issuer certificate";
            case 23:                         return "certificate revoked";
            case 24:                         return "invalid CA certificate";
            case 25:                         return "path length constraint exceeded";
            case 26:                         return "unsupported certificate purpose";
            case 89:                         return "basic constraints of CA cert not marked critical";
            default:                         return "X509_V error";
        }
    }
}
