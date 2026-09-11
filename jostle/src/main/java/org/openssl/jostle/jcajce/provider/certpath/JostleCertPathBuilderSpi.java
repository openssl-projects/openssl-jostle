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
import java.security.NoSuchProviderException;
import java.security.Provider;
import org.openssl.jostle.jcajce.provider.binding.ProviderBinding;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathParameters;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * PKIX certification path building.
 * <p>
 * The target is selected in JAVA, by the caller's {@link X509CertSelector} over
 * the {@code CertStore} contents; OpenSSL then builds the chain from every
 * certificate supplied. Parameter handling is shared with
 * {@link JostleCertPathValidatorSpi} — see its javadoc for what is honoured,
 * refused and ignored, all of which applies here too.
 */
public class JostleCertPathBuilderSpi
    extends CertPathBuilderSpi
{
    private final CertPathNI ni;

    /**
     * Which provider this SPI belongs to — instance when registered, name in
     * MT-14's unbound realm. One fact, one field; see {@link ProviderBinding}.
     */
    private final ProviderBinding binding;

    public JostleCertPathBuilderSpi()
    {
        this(org.openssl.jostle.jcajce.provider.NISelector.CertPathNI, null);
    }

    public JostleCertPathBuilderSpi(Provider providerInstance)
    {
        this(org.openssl.jostle.jcajce.provider.NISelector.CertPathNI, providerInstance);
    }

    public JostleCertPathBuilderSpi(CertPathNI ni)
    {
        this(ni, null);
    }

    public JostleCertPathBuilderSpi(CertPathNI ni, Provider providerInstance)
    {
        this.ni = ni;
        this.binding = (providerInstance != null)
                ? ProviderBinding.of(providerInstance)
                : ProviderBinding.ofName(
                        org.openssl.jostle.jcajce.provider.JostleProvider.PROVIDER_NAME);
    }

    /**
     * The X.509 factory the built chain is decoded through.
     *
     * <p>The certificates it produces are this SPI's result — they carry the
     * public key returned in the {@link PKIXCertPathBuilderResult} — so an
     * unpinned resolution would let an arbitrary provider decide what we hand
     * back. {@code getInstance(String, Provider)} reads the provider OBJECT
     * and never consults the registry.
     *
     * <p>A directly-constructed SPI has no provider and can only resolve by
     * name, which still refuses to reach outside Jostle.
     */
    private CertificateFactory x509Factory() throws CertificateException
    {
        if (binding.instance() != null)
        {
            return CertificateFactory.getInstance("X.509", binding.instance());
        }
        try
        {
            return CertificateFactory.getInstance("X.509", binding.name());
        }
        catch (NoSuchProviderException e)
        {
            CertificateException ce =
                    new CertificateException("Jostle provider is not registered");
            ce.initCause(e);
            throw ce;
        }
    }

    @Override
    public CertPathBuilderResult engineBuild(CertPathParameters params)
            throws CertPathBuilderException, InvalidAlgorithmParameterException
    {
        if (!(params instanceof PKIXBuilderParameters))
        {
            throw new InvalidAlgorithmParameterException(
                    "expected PKIXBuilderParameters, got "
                            + (params == null ? "null" : params.getClass().getName()));
        }
        PKIXBuilderParameters pkix = (PKIXBuilderParameters) params;
        CertPathParams.refuseUnsupported(pkix);

        CertSelector selector = pkix.getTargetCertConstraints();
        if (selector == null)
        {
            // Native asserts a target; refuse here so the assert is
            // unreachable from a caller.
            throw new InvalidAlgorithmParameterException(
                    "no target certificate constraints: this builder selects the target in Java, "
                            + "so a selector is required");
        }

        List<X509Certificate> pool = pool(pkix);
        List<X509Certificate> targets = new ArrayList<X509Certificate>();
        for (X509Certificate c : pool)
        {
            if (selector.match(c))
            {
                targets.add(c);
            }
        }
        if (targets.isEmpty())
        {
            throw new CertPathBuilderException(
                    "no certificate in the supplied CertStores matches the target constraints");
        }

        CertPathValidatorException last = null;
        for (X509Certificate target : targets)
        {
            try
            {
                return buildFrom(pkix, pool, target);
            }
            catch (CertPathValidatorException e)
            {
                // Several certificates can match a selector; take each in turn
                // and report the last failure if none builds.
                last = e;
            }
        }
        throw new CertPathBuilderException("no path could be built to any matching target", last);
    }

    /**
     * B1: {@code maxPathLength} is the caller's constraint, so ignoring it
     * would accept a path they ruled out. JCE counts the NON-SELF-ISSUED
     * intermediate certificates — the target is not an intermediate, and a
     * self-issued certificate does not lengthen a path (RFC 5280 6.1).
     * Enforced in Java: OpenSSL's own depth limit counts differently and is
     * deliberately left out of it.
     */
    private static void enforceMaxPathLength(PKIXBuilderParameters pkix,
                                             List<X509Certificate> pathCerts)
            throws CertPathBuilderException
    {
        int max = pkix.getMaxPathLength();
        if (max < 0)
        {
            return;   // -1 is unlimited
        }
        int intermediates = 0;
        for (int i = 1; i < pathCerts.size(); i++)   // index 0 is the target
        {
            X509Certificate c = pathCerts.get(i);
            if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal()))
            {
                intermediates++;
            }
        }
        if (intermediates > max)
        {
            throw new CertPathBuilderException(
                    "the built path has " + intermediates + " non-self-issued intermediate "
                            + "certificates, which exceeds maxPathLength " + max);
        }
    }

    private static List<X509Certificate> pool(PKIXBuilderParameters pkix)
            throws InvalidAlgorithmParameterException
    {
        List<X509Certificate> out = new ArrayList<X509Certificate>();
        for (CertStore store : pkix.getCertStores())
        {
            Collection<? extends Certificate> found;
            try
            {
                found = store.getCertificates(null);
            }
            catch (Exception e)
            {
                throw new InvalidAlgorithmParameterException("a CertStore could not be read: " + e);
            }
            for (Certificate c : found)
            {
                if (!(c instanceof X509Certificate))
                {
                    throw new InvalidAlgorithmParameterException(
                            "a CertStore holds a non-X509Certificate: " + c.getClass().getName());
                }
                out.add((X509Certificate) c);
            }
        }
        return out;
    }

    /**
     * Hand OpenSSL the target plus every other supplied certificate as
     * untrusted and let it build; the result CertPath is the chain it built,
     * minus the anchor, which a CertPath never contains.
     */
    private CertPathBuilderResult buildFrom(PKIXBuilderParameters pkix,
                                            List<X509Certificate> pool,
                                            X509Certificate target)
            throws CertPathValidatorException, CertPathBuilderException
    {
        List<X509Certificate> untrusted = new ArrayList<X509Certificate>();
        for (X509Certificate c : pool)
        {
            if (c != target)
            {
                untrusted.add(c);
            }
        }

        CertPathCall call = CertPathCall.forBuild(pkix, untrusted, target);
        int rc = ni.ni_verify(call.der, call.sizes, call.count, call.anchorCount,
                call.timeSecs, 1, call.chainOut, call.outInfo);
        if (rc == org.openssl.jostle.jcajce.provider.ErrorCode.JO_CERT_DECODE_FAILED.getCode())
        {
            throw new CertPathValidatorException("a supplied certificate is not valid DER X.509");
        }
        ni.baseErrorHandler(rc);

        int error = call.outInfo[0];
        if (error != 0)
        {
            throw CertPathErrors.toValidatorException(error, call.outInfo[1], null);
        }

        try
        {
            CertificateFactory cf = x509Factory();
            List<X509Certificate> built = call.builtCertificates(cf);
            if (built.size() < 2)
            {
                throw new CertPathBuilderException("OpenSSL returned no usable chain");
            }
            // The last element is the anchor; a CertPath excludes it.
            List<X509Certificate> pathCerts = new ArrayList<X509Certificate>(
                    built.subList(0, built.size() - 1));
            enforceMaxPathLength(pkix, pathCerts);
            CertPath cp = cf.generateCertPath(pathCerts);
            PKIXCertPathValidatorResult vr = new PKIXCertPathValidatorResult(
                    call.resolveAnchor(pkix), null, pathCerts.get(0).getPublicKey());
            return new PKIXCertPathBuilderResult(cp, vr.getTrustAnchor(), null,
                    pathCerts.get(0).getPublicKey());
        }
        catch (java.security.cert.CertificateException e)
        {
            throw new CertPathBuilderException("the built chain could not be decoded", e);
        }
    }
}
