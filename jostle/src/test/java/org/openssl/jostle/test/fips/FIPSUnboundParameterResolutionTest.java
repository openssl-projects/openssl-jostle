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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.blockcipher.AESCCMCipherSpi;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * An unbound BASE cipher is never served by JSLFIPS — the real crossing the
 * removed fallback performed.
 *
 * <p>A directly-constructed SPI has no provider instance (MT-14's unbound
 * realm) and resolves its parameters by NAME. Until 2026-09-11 that name
 * resolution fell back to the other Jostle provider, so with JSL absent a
 * base cipher's parameters came from the FIPS module's provider, silently.
 * Both providers register the same pure-Java codec, so no output could show
 * it.
 *
 * <p>The base twin of this class,
 * {@code JostleAlgorithmParametersTest}, pins the same line without a module.
 * This one is FIPS-named so the module-configuration sweep selects it.
 */
public class FIPSUnboundParameterResolutionTest
{
    /** Exposes the protected SPI entry point; nothing else. */
    private static final class ExposedCcm
            extends AESCCMCipherSpi
    {
        void init(Key key) throws Exception
        {
            engineInit(Cipher.ENCRYPT_MODE, key, (SecureRandom) null);
        }

        AlgorithmParameters parameters()
        {
            return engineGetParameters();
        }
    }

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
    public void anUnboundBaseCipherIsNotServedByTheFipsProvider() throws Exception
    {
        Provider fips = FIPSTestUtil.assumeFipsProvider();

        ExposedCcm spi = new ExposedCcm();
        spi.init(new SecretKeySpec(new byte[16], "AES"));

        AlgorithmParameters control = spi.parameters();
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, control.getProvider().getName(),
                "control: with its own provider registered the unbound SPI resolves to it");

        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Security.removeProvider(JostleProvider.PROVIDER_NAME);
        try
        {
            Assertions.assertNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                    "vacuity guard: the SPI's own provider must actually be unregistered");
            Assertions.assertNotNull(Security.getProvider(JostleFIPSProvider.PROVIDER_NAME),
                    "vacuity guard: JSLFIPS must be registered, or there is nothing to borrow");
            Assertions.assertNotNull(
                    AlgorithmParameters.getInstance("CCM", fips),
                    "vacuity guard: JSLFIPS must actually serve CCM parameters");

            Assertions.assertThrows(ProviderException.class, spi::parameters,
                    "a base cipher must fail rather than take its parameters from JSLFIPS");
        }
        finally
        {
            Security.addProvider(jsl);
        }
    }
}
