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
import java.security.cert.CertPath;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertPathValidatorResult;
import java.security.cert.CertPathValidatorSpi;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * PKIX certification path validation over OpenSSL's {@code X509_verify_cert}.
 *
 * <h2>Parameters</h2>
 * <b>Honoured:</b> the validation date ({@code getDate()}, else now); the trust
 * anchors, which must carry a certificate; {@code X509_V_FLAG_X509_STRICT},
 * always on.
 * <p>
 * <b>Also honoured: revocation.</b> {@code isRevocationEnabled()} — which
 * defaults to TRUE — turns on CRL checking for the WHOLE path, over the CRLs
 * the caller's {@code CertStore}s supply. A certificate in the path with no
 * usable CRL is an UNDETERMINED_REVOCATION_STATUS failure, not a pass.
 * <p>
 * <b>Refused typed</b>, rather than ignored, because ignoring them would return
 * a green result for a check that never ran: any initial policy set,
 * explicit-policy / policy-mapping-inhibited / any-policy-inhibited set away
 * from their defaults, and a non-empty {@code PKIXCertPathChecker} list —
 * which is also what keeps {@code PKIXRevocationChecker}, and so OCSP, out.
 * <p>
 * <b>Ignored, deliberately:</b> {@code sigProvider} — OpenSSL performs the
 * signature verification, so no JCA provider is consulted; the
 * {@code policyQualifiersRejected}, which only matters once policies are
 * processed.
 * <p>
 * <b>The CertStores are read, and never for path members.</b> With revocation
 * on, their CRLs AND their certificates are handed to OpenSSL — the
 * certificates because an indirect CRL cannot be validated without its
 * issuer's certificate, which PKITS and real callers put in a store rather
 * than in the path. They are marshalled as untrusted only: the built-chain
 * check still requires the chain OpenSSL produced to be the path that was
 * given, so a store certificate turning up IN the chain is a failure, not a
 * silent substitution. {@code maxPathLength} belongs to the BUILDER and is honoured
 * there; this validator takes the path as given and does not choose its
 * length. The result's policy tree is {@code null}: this phase does no
 * policy processing, and a fabricated tree would be worse than none.
 * <p>
 * <b>One consequence of building through OpenSSL:</b> a SELF-ISSUED
 * certificate that OpenSSL leaves out of its chain is not validated at all —
 * not even its validity dates — because it never enters the chain. Measured on
 * PKITS 4.5.4 (the new-with-old rollover certificate) and 4.5.6 (the CRL
 * signer, which phase 2 validates when it processes CRLs).
 */
public class JostleCertPathValidatorSpi
    extends CertPathValidatorSpi
{
    private final CertPathNI ni;

    public JostleCertPathValidatorSpi()
    {
        this(org.openssl.jostle.jcajce.provider.NISelector.CertPathNI);
    }

    public JostleCertPathValidatorSpi(CertPathNI ni)
    {
        this.ni = ni;
    }

    @Override
    public CertPathValidatorResult engineValidate(CertPath certPath, CertPathParameters params)
            throws CertPathValidatorException, InvalidAlgorithmParameterException
    {
        if (!(params instanceof PKIXParameters))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected PKIXParameters, got "
                            + (params == null ? "null" : params.getClass().getName()));
        }
        PKIXParameters pkix = (PKIXParameters) params;
        CertPathParams.refuseUnsupported(pkix);

        if (!"X.509".equals(certPath.getType()))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected an X.509 CertPath, got " + certPath.getType());
        }
        List<? extends Certificate> certs = certPath.getCertificates();
        for (Certificate c : certs)
        {
            if (!(c instanceof X509Certificate))
            {
                throw new InvalidAlgorithmParameterException(
                        "the certification path contains a non-X509Certificate: "
                                + c.getClass().getName());
            }
        }
        if (certs.isEmpty())
        {
            // Native asserts a non-empty path as an invariant, so it is refused
            // here — the assert must be unreachable from a caller.
            throw new CertPathValidatorException("certification path is empty");
        }

        CertPathCall call = CertPathCall.build(pkix, certs, CertPathCall.crlsFrom(pkix),
                CertPathCall.extraCertsFrom(pkix, certs));
        int rc = ni.ni_verify(call.der, call.sizes, call.count, call.crlCount, call.anchorCount,
                call.timeSecs, 1, call.revocation, call.chainOut, call.outInfo);

        if (rc == org.openssl.jostle.jcajce.provider.ErrorCode.JO_CRL_DECODE_FAILED.getCode())
        {
            // outInfo[1] indexes the CRLs, which belong to no path element, so
            // the exception carries -1 rather than a misleading certificate.
            throw new CertPathValidatorException(
                    "a supplied CRL is not valid DER X.509, at CRL index " + call.outInfo[1],
                    null, certPath, -1);
        }

        // Intercepted BEFORE baseErrorHandler, which throws IllegalStateException
        // for any code its switch does not list — the same reason the seed
        // getters intercept JO_SEED_UNAVAILABLE. Without this the typed
        // exception below is unreachable.
        if (rc == org.openssl.jostle.jcajce.provider.ErrorCode.JO_CERT_DECODE_FAILED.getCode())
        {
            // outInfo[1] is the index into the marshalled array: anchors first,
            // then the path REVERSED, so map it back to the caller's ordering.
            int nativeIndex = call.outInfo[1];
            int pathIndex = call.toPathIndex(nativeIndex, certs.size());
            throw new CertPathValidatorException(
                    "a certificate in the path is not valid DER X.509", null, certPath, pathIndex);
        }
        ni.baseErrorHandler(rc);

        int error = call.outInfo[0];
        if (error != 0)
        {
            throw CertPathErrors.toValidatorException(error, call.outInfo[1], certPath);
        }

        // P4: the validator does not rebuild. A chain OpenSSL completed
        // differently is a failure OF THE GIVEN PATH, not a success.
        call.assertBuiltChainMatches(certs, certPath);

        TrustAnchor anchor = call.resolveAnchor(pkix);
        return new PKIXCertPathValidatorResult(anchor, null,
                ((X509Certificate) certs.get(0)).getPublicKey());
    }
}
