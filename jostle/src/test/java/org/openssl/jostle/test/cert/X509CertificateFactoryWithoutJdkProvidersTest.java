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
import org.openssl.jostle.jcajce.provider.cert.X509CertificateFactorySpi;
import org.openssl.jostle.test.certpath.PkitsCertificates;
import org.openssl.jostle.util.Arrays;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
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
    private static final String SUN_RSA_SIGN = "SunRsaSign";

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
        // Arrays is qualified where the JDK's is meant: jostle's of that name is imported
        java.util.Arrays.fill(garbage, (byte) 0xFF);
        Assertions.assertThrows(CertificateException.class,
                () -> cf.generateCertificate(new ByteArrayInputStream(garbage)));
    }

    /**
     * With nothing to fall back to, a Signature the bound provider does not serve fails with the ORIGINAL
     * exception, naming the algorithm and the provider, not the search's own message.
     */
    @Test
    public void anUnservedSignatureWithNothingToFallBackToThrowsTheOriginalException()
        throws Exception
    {
        byte[] der = VerifyCascadeFixtures.selfSigned(VerifyCascadeFixtures.RIPEMD160_RSA,
                VerifyCascadeFixtures.rsaKeyPair(), "CN=Unserved");
        Provider jsl = onlyJostle();
        X509Certificate c = VerifyCascadeFixtures.parse(CertificateFactory.getInstance("X.509", jsl), der);
        PublicKey key = c.getPublicKey();

        NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class, () -> c.verify(key));
        Assertions.assertSame(NoSuchAlgorithmException.class, e.getClass());
        Assertions.assertTrue(e.getMessage().contains(VerifyCascadeFixtures.RIPEMD160_RSA_OID), e.getMessage());
        Assertions.assertTrue(e.getMessage().contains(jsl.getName()), e.getMessage());
    }

    /**
     * A factory built with the public name-only constructor resolves its provider by name; with that provider
     * removed, verify falls back to search order, and with nothing installed the original refusal stands.
     */
    @Test
    public void aNameOnlyFactoryWhoseProviderIsGoneVerifiesThroughSearchOrder()
        throws Exception
    {
        KeyPair kp = VerifyCascadeFixtures.rsaKeyPair();
        byte[] der = VerifyCascadeFixtures.selfSigned(VerifyCascadeFixtures.SHA256_RSA, kp, "CN=Name Only");
        byte[] otherDer = VerifyCascadeFixtures.selfSigned(VerifyCascadeFixtures.SHA256_RSA,
                VerifyCascadeFixtures.rsaKeyPair(), "CN=Other");
        Provider sunRsaSign = Security.getProvider(SUN_RSA_SIGN);
        Assertions.assertNotNull(sunRsaSign, "the recorder delegates to " + SUN_RSA_SIGN);

        Provider jsl = new JostleProvider();
        ProviderRegistrySnapshot.append(jsl);
        X509CertificateFactorySpi spi = new X509CertificateFactorySpi(jsl.getName(), false);
        X509Certificate c = (X509Certificate) spi.engineGenerateCertificate(new ByteArrayInputStream(der));
        PublicKey key = c.getPublicKey();
        PublicKey unrelated =
                ((X509Certificate) spi.engineGenerateCertificate(new ByteArrayInputStream(otherDer))).getPublicKey();

        Security.removeProvider(jsl.getName());
        RecordingSignatureProvider recorder = new RecordingSignatureProvider(sunRsaSign, c.getSigAlgName());
        ProviderRegistrySnapshot.insertFirst(recorder);
        c.verify(key);
        Assertions.assertEquals(1, recorder.verifications(), "the verify reached search order");
        Assertions.assertThrows(SignatureException.class, () -> c.verify(unrelated));

        ProviderRegistrySnapshot.empty();
        ProviderException e = Assertions.assertThrows(ProviderException.class, () -> c.verify(key));
        Assertions.assertEquals("no provider named " + jsl.getName() + " to verify through", e.getMessage());
    }
}
