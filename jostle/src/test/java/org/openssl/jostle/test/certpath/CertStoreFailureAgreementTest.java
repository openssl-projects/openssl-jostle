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

package org.openssl.jostle.test.certpath;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * A CertStore that fails while the PKIX builder or validator reads it. A RuntimeException passes through
 * unchanged, as from SUN and BouncyCastle 1.87. A CertStoreException becomes the operation's own checked
 * exception with the CertStoreException kept as the cause, BouncyCastle's shape; SUN instead skips the failing
 * store, which is pinned beside ours as a divergence: a failing store must not silently shrink the pool.
 */
public class CertStoreFailureAgreementTest
{
    private static final String JSL = JostleProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final String EE = "ValidCertificatePathTest1EE.crt";
    private static final String CA = "GoodCACert.crt";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static X509Certificate cert(String provider, String name) throws Exception
    {
        return (X509Certificate) CertificateFactory.getInstance("X.509", provider)
                .generateCertificate(new ByteArrayInputStream(PkitsCertificates.der(name)));
    }

    private static Set<TrustAnchor> anchors(String provider) throws Exception
    {
        return Collections.singleton(new TrustAnchor(cert(provider, PkitsCertificates.ANCHOR), null));
    }

    /** PKITS 4.1.1 built from a good Collection store beside a store that throws. */
    private static void build(String provider, boolean checked, boolean revocation) throws Exception
    {
        X509CertSelector target = new X509CertSelector();
        target.setCertificate(cert(provider, EE));
        PKIXBuilderParameters p = new PKIXBuilderParameters(anchors(provider), target);
        p.setRevocationEnabled(revocation);
        List<Object> good = new ArrayList<Object>();
        good.add(cert(provider, EE));
        good.add(cert(provider, CA));
        p.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(good)));
        p.addCertStore(OrderedCertStores.throwing(checked));
        CertPathBuilder.getInstance("PKIX", provider).build(p);
    }

    /** PKITS 4.1.1 validated with only a store that throws. */
    private static void validate(String provider, boolean checked, boolean revocation) throws Exception
    {
        List<Certificate> certs = new ArrayList<Certificate>();
        certs.add(cert(provider, EE));
        certs.add(cert(provider, CA));
        CertPath path = CertificateFactory.getInstance("X.509", provider).generateCertPath(certs);
        PKIXParameters p = new PKIXParameters(anchors(provider));
        p.setRevocationEnabled(revocation);
        p.addCertStore(OrderedCertStores.throwing(checked));
        CertPathValidator.getInstance("PKIX", provider).validate(path, p);
    }

    private static boolean causedBy(Throwable t, Class<? extends Throwable> type, String message)
    {
        for (Throwable c = t.getCause(); c != null; c = c.getCause())
        {
            if (type.isInstance(c) && message.equals(c.getMessage()))
            {
                return true;
            }
        }
        return false;
    }

    /** A RuntimeException from a store read by the builder passes through unchanged, as from SUN and BC. */
    @Test
    public void builderRuntimeExceptionPassesThrough() throws Exception
    {
        for (String p : new String[]{JSL, "SUN", BC})
        {
            for (boolean revocation : new boolean[]{false, true})
            {
                IllegalStateException e = assertThrows(IllegalStateException.class,
                        () -> build(p, false, revocation), p);
                Assertions.assertEquals("the store broke reading certificates", e.getMessage(), p);
            }
        }
    }

    /**
     * A CertStoreException from a store read by the builder is CertPathBuilderException with the
     * CertStoreException as its cause; BC's carries it further down its cause chain; SUN skips the store and
     * builds from the others.
     */
    @Test
    public void builderCertStoreExceptionIsTypedWithItsCause() throws Exception
    {
        for (boolean revocation : new boolean[]{false, true})
        {
            CertPathBuilderException ours = assertThrows(CertPathBuilderException.class,
                    () -> build(JSL, true, revocation));
            Assertions.assertTrue(ours.getCause() instanceof CertStoreException, String.valueOf(ours.getCause()));
            Assertions.assertEquals("the store refuses to read certificates", ours.getCause().getMessage());

            CertPathBuilderException bc = assertThrows(CertPathBuilderException.class,
                    () -> build(BC, true, revocation));
            Assertions.assertTrue(causedBy(bc, CertStoreException.class, "the store refuses to read certificates"),
                    "BC keeps the CertStoreException in its cause chain");
        }
        build("SUN", true, false);
    }

    /** A RuntimeException from a store read by the validator for revocation passes through unchanged. */
    @Test
    public void validatorRuntimeExceptionPassesThrough() throws Exception
    {
        for (String p : new String[]{JSL, "SUN", BC})
        {
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> validate(p, false, true), p);
            Assertions.assertEquals("the store broke reading CRLs", e.getMessage(), p);
        }
    }

    /**
     * A CertStoreException from a store read by the validator for revocation is CertPathValidatorException with
     * the CertStoreException as its cause; BC's carries it further down; SUN skips the store and then cannot
     * determine revocation status.
     */
    @Test
    public void validatorCertStoreExceptionIsTypedWithItsCause() throws Exception
    {
        CertPathValidatorException ours = assertThrows(CertPathValidatorException.class,
                () -> validate(JSL, true, true));
        Assertions.assertTrue(ours.getCause() instanceof CertStoreException, String.valueOf(ours.getCause()));
        Assertions.assertEquals("the store refuses to read CRLs", ours.getCause().getMessage());

        CertPathValidatorException bc = assertThrows(CertPathValidatorException.class,
                () -> validate(BC, true, true));
        Assertions.assertTrue(causedBy(bc, CertStoreException.class, "the store refuses to read CRLs"),
                "BC keeps the CertStoreException in its cause chain");

        CertPathValidatorException sun = assertThrows(CertPathValidatorException.class,
                () -> validate("SUN", true, true));
        Assertions.assertEquals(CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS,
                sun.getReason());
    }

    /** With revocation off the validator reads no store, so neither kind of failure is seen by any of the three. */
    @Test
    public void validatorWithoutRevocationReadsNoStore() throws Exception
    {
        for (String p : new String[]{JSL, "SUN", BC})
        {
            validate(p, true, false);
            validate(p, false, false);
        }
    }
}
