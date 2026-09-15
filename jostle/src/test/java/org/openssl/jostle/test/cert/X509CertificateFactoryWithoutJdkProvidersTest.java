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

package org.openssl.jostle.test.cert;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.test.certpath.PkitsCertificates;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * THE REGRESSION TEST: the X.509 CertificateFactory works with none of the JDK
 * providers installed.
 *
 * <p>The reported defect was not "certificate parsing is unavailable" but "the
 * service cannot be CREATED": the factory resolved
 * {@code CertificateFactory.getInstance("X.509", "SUN")} in its CONSTRUCTOR,
 * so on a JVM that removes the JDK providers — or filters them with
 * {@code jdk.security.providers.filter} — the failure arrived at
 * {@code getInstance} rather than at the operation. Hence the first assertion
 * below is simply that getInstance returns.
 *
 * <p>It empties the GLOBAL provider registry and restores it in an
 * {@code @AfterEach} that runs whatever the test does, then ASSERTS the
 * restoration. That harness is not belt-and-braces: a cell elsewhere in this
 * suite once left the registry empty and failed 20 tests across three
 * unrelated classes scheduled into the same JVM seconds later, because their
 * seeded-random helper needs SUN. {@code forkEvery = 1} does NOT contain it.
 */
public class X509CertificateFactoryWithoutJdkProvidersTest
{
    /** The registry as it was, in order, so it can be put back exactly. */
    private Provider[] original;

    @BeforeEach
    public void snapshotTheRegistry()
    {
        original = Security.getProviders();
    }

    @AfterEach
    public void restoreTheRegistry()
        throws Exception
    {
        if (original == null)
        {
            return;
        }
        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        // insertProviderAt is 1-based and preserves precedence; addProvider
        // appends and silently reorders.
        for (int i = 0; i < original.length; i++)
        {
            Security.insertProviderAt(original[i], i + 1);
        }

        Provider[] restored = Security.getProviders();
        Assertions.assertEquals(original.length, restored.length,
                "provider count not restored: the next class in this JVM will see a different registry");
        for (int i = 0; i < original.length; i++)
        {
            Assertions.assertEquals(original[i].getName(), restored[i].getName(),
                    "provider at position " + i + " not restored");
        }
        // Behavioural witness of a different shape from the name comparison:
        // the exact lookup whose absence failed those 20 tests.
        Assertions.assertDoesNotThrow(() -> SecureRandom.getInstance("SHA1PRNG"),
                "SHA1PRNG is unavailable after the restore");
    }

    private static Provider onlyJostle()
    {
        for (Provider installed : Security.getProviders())
        {
            Security.removeProvider(installed.getName());
        }
        Assertions.assertEquals(0, Security.getProviders().length,
                "the registry was not emptied, so this proves nothing about a JDK-free deployment");

        Provider jsl = new JostleProvider();
        Security.addProvider(jsl);
        Assertions.assertEquals(1, Security.getProviders().length);
        return jsl;
    }

    @Test
    public void theFactoryIsCONSTRUCTIBLEWithNoJdkProviders()
        throws Exception
    {
        Provider jsl = onlyJostle();

        // The defect, precisely: this line threw.
        CertificateFactory cf = CertificateFactory.getInstance("X.509", jsl);
        Assertions.assertSame(jsl, cf.getProvider());

        // ... and so did this, through the alias.
        Assertions.assertSame(jsl, CertificateFactory.getInstance("X509", jsl).getProvider());
    }

    @Test
    public void certificatesParseAndAnswerWithNoJdkProviders()
        throws Exception
    {
        Provider jsl = onlyJostle();
        byte[] der = PkitsCertificates.der("GoodCACert.crt");

        CertificateFactory cf = CertificateFactory.getInstance("X.509", jsl);
        X509Certificate c = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));

        Assertions.assertEquals(3, c.getVersion());
        Assertions.assertEquals("SHA256withRSA", c.getSigAlgName());
        Assertions.assertEquals("CN=Good CA, O=Test Certificates 2011, C=US",
                c.getSubjectDN().getName());
        Assertions.assertTrue(Arrays.areEqual(der, c.getEncoded()),
                "a DER certificate re-encodes to the bytes it came from");

        // The key is rebuilt through JSL's own KeyFactory, with no JDK provider
        // anywhere to fall through to.
        PublicKey key = c.getPublicKey();
        Assertions.assertEquals("RSA", key.getAlgorithm());
        Assertions.assertTrue(key.getClass().getName().startsWith("org.openssl.jostle."),
                "expected a Jostle key, got " + key.getClass().getName());
    }

    /**
     * The negative half: without it, a factory that returned a constant would
     * pass the cell above.
     */
    @Test
    public void garbageIsStillRefusedWithNoJdkProviders()
        throws Exception
    {
        Provider jsl = onlyJostle();
        CertificateFactory cf = CertificateFactory.getInstance("X.509", jsl);

        byte[] garbage = new byte[32];
        java.util.Arrays.fill(garbage, (byte) 0xFF);
        Assertions.assertThrows(java.security.cert.CertificateException.class,
                () -> cf.generateCertificate(new ByteArrayInputStream(garbage)));
    }
}
