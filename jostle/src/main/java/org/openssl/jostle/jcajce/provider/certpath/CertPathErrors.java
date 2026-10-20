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
import java.security.cert.Certificate;
import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;

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
    private static final int ERR_CERT_REVOKED = 23;
    private static final int ERR_INVALID_CA = 79;

    /* keyCertSign's bit in X509Certificate.getKeyUsage(). */
    private static final int KEY_CERT_SIGN = 5;

    /* No anchor issues the chain: NO_TRUST_ANCHOR. */
    private static final int ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
    private static final int ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
    private static final int ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
    private static final int ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
    private static final int ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE = 21;
    private static final int ERR_CERT_UNTRUSTED = 27;

    /* The PKIXReason families, each as the JDK's validator reports it. */
    private static final int ERR_PATH_LENGTH_EXCEEDED = 25;
    private static final int ERR_SUBJECT_ISSUER_MISMATCH = 29;
    private static final int ERR_AKID_SKID_MISMATCH = 30;
    private static final int ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
    private static final int ERR_KEYUSAGE_NO_CERTSIGN = 32;
    private static final int ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
    private static final int ERR_INVALID_NON_CA = 37;
    private static final int ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;
    private static final int ERR_INVALID_POLICY_EXTENSION = 42;
    private static final int ERR_NO_EXPLICIT_POLICY = 43;
    private static final int ERR_PERMITTED_VIOLATION = 47;
    private static final int ERR_EXCLUDED_VIOLATION = 48;
    private static final int ERR_SUBTREE_MINMAX = 49;
    private static final int ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51;
    private static final int ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52;
    private static final int ERR_UNSUPPORTED_NAME_SYNTAX = 53;
    private static final int ERR_CA_BCONS_NOT_CRITICAL = 89;
    private static final int ERR_CA_CERT_MISSING_KEY_USAGE = 92;

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
        // OpenSSL counts depth from the target; so does CertPath. A depth past
        // the path's end is the anchor, which CertPath does not contain, and
        // the JCE contract wants -1 there rather than an out-of-range index.
        // OpenSSL names no certificate for code 43, so its depth of 0 is not the target.
        int index = error == ERR_NO_EXPLICIT_POLICY ? -1 : depth;
        if (path == null || index < 0 || index >= path.getCertificates().size())
        {
            index = -1;
        }

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
            case ERR_UNABLE_TO_GET_ISSUER_CERT:
            case ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case ERR_SELF_SIGNED_CERT_IN_CHAIN:
            case ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            case ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            case ERR_CERT_UNTRUSTED:
                reason = PKIXReason.NO_TRUST_ANCHOR;
                break;
            case ERR_INVALID_CA:
                reason = invalidCaReason(path, index);
                break;
            case ERR_INVALID_NON_CA:
            case ERR_CA_BCONS_NOT_CRITICAL:
                reason = PKIXReason.NOT_CA_CERT;
                break;
            case ERR_PATH_LENGTH_EXCEEDED:
                reason = PKIXReason.PATH_TOO_LONG;
                break;
            case ERR_SUBJECT_ISSUER_MISMATCH:
            case ERR_AKID_SKID_MISMATCH:
            case ERR_AKID_ISSUER_SERIAL_MISMATCH:
                reason = PKIXReason.NAME_CHAINING;
                break;
            case ERR_KEYUSAGE_NO_CERTSIGN:
            case ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
            case ERR_CA_CERT_MISSING_KEY_USAGE:
                reason = PKIXReason.INVALID_KEY_USAGE;
                break;
            case ERR_UNHANDLED_CRITICAL_EXTENSION:
                reason = PKIXReason.UNRECOGNIZED_CRIT_EXT;
                break;
            case ERR_INVALID_POLICY_EXTENSION:
            case ERR_NO_EXPLICIT_POLICY:
                reason = PKIXReason.INVALID_POLICY;
                break;
            case ERR_PERMITTED_VIOLATION:
            case ERR_EXCLUDED_VIOLATION:
            case ERR_SUBTREE_MINMAX:
            case ERR_UNSUPPORTED_CONSTRAINT_TYPE:
            case ERR_UNSUPPORTED_CONSTRAINT_SYNTAX:
            case ERR_UNSUPPORTED_NAME_SYNTAX:
                reason = PKIXReason.INVALID_NAME;
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

        return new CertPathValidatorException(
                "certification path validation failed: " + error + " " + ni.ni_errorText(error),
                null, path, index, reason);
    }

    /**
     * Code 79 covers two refusals the JDK reports apart: a keyUsage without
     * keyCertSign is INVALID_KEY_USAGE, a certificate that is not a CA is
     * NOT_CA_CERT. Only the certificate OpenSSL names is read. A certificate
     * lacking both a CA basicConstraints and keyCertSign takes INVALID_KEY_USAGE
     * here; no PKITS row has that shape, so the arm is unwitnessed. The builder
     * passes no path, so its 79 is always NOT_CA_CERT, uncompared: the JDK's
     * builder reports no reason.
     */
    private static CertPathValidatorException.Reason invalidCaReason(CertPath path, int index)
    {
        if (index >= 0)
        {
            Certificate c = path.getCertificates().get(index);
            if (c instanceof X509Certificate)
            {
                boolean[] keyUsage = ((X509Certificate) c).getKeyUsage();
                if (keyUsage != null && (keyUsage.length <= KEY_CERT_SIGN || !keyUsage[KEY_CERT_SIGN]))
                {
                    return PKIXReason.INVALID_KEY_USAGE;
                }
            }
        }
        return PKIXReason.NOT_CA_CERT;
    }
}
