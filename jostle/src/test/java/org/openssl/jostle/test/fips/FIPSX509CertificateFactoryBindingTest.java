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

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.certpath.PkitsCertificates;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * The provider-bound factory re-derives through its own INSTANCE, so an
 * unregistered JSLFIPS still decodes rather than failing loud.
 *
 * <p>The bound policy refuses to hand back a JDK key, which is right. Pinned
 * to a NAME it also refused to hand back anything at all once the name was
 * unregistered: measured before the fix, {@code getPublicKey()} threw
 * {@code ProviderException} on a factory the caller had obtained from the
 * provider object itself. Nothing about the module had changed.
 *
 * <p>Fixture is the PKITS RSA-2048 end-entity certificate, measured
 * re-derivable by JSLFIPS on this module; the runtime-generated certificates
 * belong to {@code FIPSX509CertificateFactoryTest}, which this does not touch.
 */
public class FIPSX509CertificateFactoryBindingTest
{
    private static final String EE = "ValidCertificatePathTest1EE.crt";
    /** Self-signed, so verify() against its own key is a real signature check. */
    private static final String ANCHOR = "TrustAnchorRootCertificate.crt";

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void anUnregisteredFipsInstanceStillDecodesItsOwnKeys() throws Exception
    {
        Provider fips = FIPSTestUtil.assumeFipsProvider();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", fips);

        X509Certificate control = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(PkitsCertificates.der(EE)));
        Assertions.assertTrue(
                control.getPublicKey().getClass().getName().startsWith("org.openssl.jostle."),
                "control: the registered bound factory re-derives through JSLFIPS");

        // The FIPS provider is constructed once per JVM (the native lib ctx
        // guard is one-shot), so the unregistered instance is obtained by
        // removing the registered one rather than building a second.
        Security.removeProvider(JostleFIPSProvider.PROVIDER_NAME);
        try
        {
            Assertions.assertNull(Security.getProvider(JostleFIPSProvider.PROVIDER_NAME),
                    "vacuity guard: JSLFIPS must actually be unregistered");

            X509Certificate c = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(PkitsCertificates.der(EE)));
            PublicKey key = c.getPublicKey();

            Assertions.assertTrue(key.getClass().getName().startsWith("org.openssl.jostle."),
                    "an unregistered bound factory must still decode through its own instance;"
                            + " was " + key.getClass().getName());

            // Provenance, not equality: the key must be usable by the instance
            // the factory belongs to.
            java.security.Signature v = java.security.Signature.getInstance("SHA256withRSA", fips);
            v.initVerify(key);
        }
        finally
        {
            Security.addProvider(fips);
        }
    }

    /**
     * The bound one-argument {@code verify()} resolves its Signature from the
     * factory's own instance too. Pinned to a NAME it threw
     * {@code NoSuchProviderException} once the name was unregistered — the
     * caller had handed the factory the provider object, so there was never
     * any doubt about which provider to use.
     */
    @Test
    public void theBoundVerifyUsesTheFactorysOwnInstance() throws Exception
    {
        Provider fips = FIPSTestUtil.assumeFipsProvider();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", fips);

        // NO registered control verify on this certificate first, deliberately.
        // SUN's factory returns the SAME X509CertImpl for a repeated DER, and
        // its verify() caches on (verifiedPublicKey.equals(key), provider
        // string) — and Jostle keys compare by ENCODING, so a re-derived key
        // from a second parse compares equal. A control verify while
        // registered therefore caches "JSLFIPS" and the call under test
        // returns without resolving anything. Measured: the first version of
        // this cell stayed GREEN under the name-pinned sabotage for exactly
        // that reason. The registered control is external — the one-argument
        // verify cell in FIPSX509CertificateFactoryTest.
        Security.removeProvider(JostleFIPSProvider.PROVIDER_NAME);
        try
        {
            Assertions.assertNull(Security.getProvider(JostleFIPSProvider.PROVIDER_NAME),
                    "vacuity guard: JSLFIPS must actually be unregistered");

            X509Certificate c = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(PkitsCertificates.der(ANCHOR)));
            c.verify(c.getPublicKey());
        }
        finally
        {
            Security.addProvider(fips);
        }
    }
}
