/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.fips;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.CertificateFactory;

/**
 * Provider-scope lock: the FIPS provider ("JSLFIPS") deliberately does NOT
 * register the PKCS12 KeyStore that the non-FIPS provider ("JSL") registers,
 * because {@code JostleFIPSProvider.setup} does not invoke {@code ProvKS}.
 * This pins that deliberate scope: {@link KeyStore#getInstance(String, String)}
 * against JSLFIPS throws while the same call against JSL succeeds in the same
 * JVM.
 *
 * <p>The X.509 CertificateFactory was originally excluded on the same
 * reasoning, then deliberately added back via {@code ProvFIPSX509} in
 * provider-bound mode (keys and verification flowing from parsed certificates
 * stay inside the FIPS boundary); its presence is asserted positively here and
 * its behaviour is owned by {@code FIPSX509CertificateFactoryTest}. Gated on
 * TEST_FIPS_LIB; skipped when unset.
 *
 * @see org.openssl.jostle.jcajce.provider.ProvKS
 * @see org.openssl.jostle.jcajce.provider.ProvX509
 */
public class FIPSNonCryptoServiceAbsenceTest
{
    // Service names registered by ProvKS / ProvX509 (base provider only).
    private static final String PKCS12_KEYSTORE = "PKCS12";
    private static final String X509_CERT_FACTORY = "X.509";

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void keyStoreAbsentAndCertificateFactoryPresentOnJslfips()
        throws Exception
    {
        ensureProviders();

        // Sanity: both providers are actually present in this JVM, so a failure
        // below is genuine service absence, not a missing provider.
        Assertions.assertNotNull(Security.getProvider(JostleFIPSProvider.PROVIDER_NAME),
                "JSLFIPS provider must be registered");
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                "JSL provider must be registered");

        // JSLFIPS does not register PKCS12: KeyStore.getInstance surfaces a
        // KeyStoreException wrapping a NoSuchAlgorithmException.
        KeyStoreException ksEx = Assertions.assertThrows(KeyStoreException.class,
                () -> KeyStore.getInstance(PKCS12_KEYSTORE, JostleFIPSProvider.PROVIDER_NAME));
        Assertions.assertTrue(combinedMessage(ksEx).contains(PKCS12_KEYSTORE),
                "KeyStore absence message should name the service: " + combinedMessage(ksEx));

        // JSLFIPS DOES register X.509 (ProvFIPSX509, provider-bound): its
        // presence is part of the pinned scope, behaviour is covered by
        // FIPSX509CertificateFactoryTest.
        Assertions.assertNotNull(
                CertificateFactory.getInstance(X509_CERT_FACTORY, JostleFIPSProvider.PROVIDER_NAME),
                "JSLFIPS must serve the X.509 CertificateFactory");

        // Same JVM: the non-FIPS provider DOES serve both, proving the absence
        // above is a deliberate FIPS-provider scope decision, not a build-wide
        // omission.
        Assertions.assertNotNull(KeyStore.getInstance(PKCS12_KEYSTORE, JostleProvider.PROVIDER_NAME),
                "JSL must serve the PKCS12 KeyStore");
        Assertions.assertNotNull(CertificateFactory.getInstance(X509_CERT_FACTORY, JostleProvider.PROVIDER_NAME),
                "JSL must serve the X.509 CertificateFactory");
    }

    /**
     * The JDK generates the algorithm-absence message text (and the concrete
     * cause type) differently across releases; join the exception and its cause
     * so the assertion can pin the stable service-name substring regardless of
     * which layer carries it.
     */
    private static String combinedMessage(final Throwable t)
    {
        final StringBuilder sb = new StringBuilder();
        Throwable cur = t;
        while (cur != null)
        {
            if (cur.getMessage() != null)
            {
                sb.append(cur.getMessage()).append('\n');
            }
            cur = cur.getCause();
        }
        return sb.toString();
    }
}
