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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;

/**
 * A JSLFIPS cipher resolves its CCM parameters from JSLFIPS, never from JSL.
 *
 * <p>The FIPS half of {@code BoundParameterResolutionTest}. Both providers
 * compute identical CCM parameters, so no output distinguishes them — the
 * discriminator is an UNREGISTERED JSLFIPS instance while JSL is registered
 * and can serve the same service. Before MT-89 that combination returned
 * {@code cipher=JSLFIPS, params from JSL}: a silent cross-provider crossing
 * of the shape MT-10 and MT-14 closed elsewhere.
 *
 * <p>Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSBoundParameterResolutionTest
{
    private static final String CCM = "AES/CCM/NoPadding";

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void ccmOnAnUnregisteredFipsInstanceDoesNotBorrowFromJsl() throws Exception
    {
        JostleFIPSProvider fips = FIPSTestUtil.assumeFipsProvider();
        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);

        // Vacuity guards: name resolution WOULD have succeeded, and from JSL.
        Assertions.assertNotNull(jsl, "JSL must be registered, or nothing could be borrowed");
        Assertions.assertNotNull(jsl.getService("AlgorithmParameters", "CCM"),
                "JSL must serve CCM parameters, or the crossing is unreachable");

        SecretKey key = aes128Key(fips);

        // The FIPS provider is constructed once per JVM (the native lib ctx
        // guard is one-shot), so the unregistered instance is obtained by
        // removing the registered one rather than building a second.
        Security.removeProvider(JostleFIPSProvider.PROVIDER_NAME);
        try
        {
            Assertions.assertNull(Security.getProvider(JostleFIPSProvider.PROVIDER_NAME),
                    "vacuity guard: JSLFIPS must actually be unregistered");

            Cipher c = Cipher.getInstance(CCM, fips);
            c.init(Cipher.ENCRYPT_MODE, key);

            AlgorithmParameters p = c.getParameters();
            Assertions.assertNotNull(p,
                    "an unregistered instance must still serve its own parameters");
            Assertions.assertSame(fips, p.getProvider(),
                    "a JSLFIPS cipher's CCM parameters must come from JSLFIPS, not JSL");
        }
        finally
        {
            Security.addProvider(fips);
        }
    }

    /** The registered path is unchanged. */
    @Test
    public void ccmThroughTheRegisteredFipsProviderStillResolves() throws Exception
    {
        JostleFIPSProvider fips = FIPSTestUtil.assumeFipsProvider();

        Cipher c = Cipher.getInstance(CCM, JostleFIPSProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, aes128Key(fips));

        AlgorithmParameters p = c.getParameters();
        Assertions.assertNotNull(p, "the registered path must still serve parameters");
        Assertions.assertEquals(JostleFIPSProvider.PROVIDER_NAME, p.getProvider().getName(),
                "and they must come from JSLFIPS");
        Assertions.assertNotNull(p.getParameterSpec(GCMParameterSpec.class),
                "and they must read back as the CCM nonce + ICV length");
    }

    private static SecretKey aes128Key(Provider provider) throws Exception
    {
        KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
        kg.init(128);
        return kg.generateKey();
    }
}
