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

package org.openssl.jostle.jcajce.provider.blockcipher;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;

/**
 * An UNBOUND SPI resolves its parameters from its own provider or from
 * nowhere.
 *
 * <p>Resolution is to the named provider or nowhere. The fallback to the
 * other Jostle provider was removed 2026-09-11 with zero measured reach (85
 * registered Cipher services across both providers, none unbound); a
 * JSLFIPS-named SPI served by JSL is the crossing MT-10 and MT-14 refuse.
 *
 * <p>In this package deliberately: the class under test is package-private,
 * and so is the SPI entry point that reaches it.
 *
 * <p>The discriminating cell is {@link #anotherProvidersNameIsNotServedByUs()}.
 * The removed arm picked "the other Jostle provider" for ANY name that was
 * not the base one, so an unregistered name that is not a Jostle provider at
 * all takes the same branch and needs no FIPS module; the real JSL/JSLFIPS
 * crossing is pinned by the FIPS twin of this class, which the module sweep
 * selects by name. Cell three is NOT a third witness — with no provider
 * registered the removed code threw as well.
 */
public class JostleAlgorithmParametersTest
{
    /**
     * A provider name nothing registers. Not a Jostle name on purpose: the
     * removed arm served any non-base name from JSL, so this reaches the same
     * branch without a token that would put this class in the FIPS module
     * sweep it has no business being in.
     */
    private static final String UNREGISTERED_PROVIDER = "NoSuchProviderForThisTest";

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** The control: the SPI's own provider serves it. */
    @Test
    public void theOwnProviderServes() throws Exception
    {
        AlgorithmParameters p =
                JostleAlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME);

        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, p.getProvider().getName(),
                "the named provider must be the one that served");
    }

    /**
     * An SPI naming a provider that is not registered is not served by JSL,
     * even though JSL is registered and can serve the algorithm. Before
     * MT-97 it was.
     */
    @Test
    public void anotherProvidersNameIsNotServedByUs() throws Exception
    {
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                "vacuity guard: JSL must be registered, or there is nothing to borrow");
        Assertions.assertNotNull(
                AlgorithmParameters.getInstance("CCM", JostleProvider.PROVIDER_NAME),
                "vacuity guard: JSL must actually serve CCM parameters");
        Assertions.assertNull(Security.getProvider(UNREGISTERED_PROVIDER),
                "vacuity guard: the named provider must be absent, or this asks nothing");

        NoSuchAlgorithmException e = Assertions.assertThrows(NoSuchAlgorithmException.class,
                () -> JostleAlgorithmParameters.getInstance("CCM", UNREGISTERED_PROVIDER),
                "an unregistered provider's SPI must fail, not be served by another provider");

        Assertions.assertEquals(
                "provider " + UNREGISTERED_PROVIDER + " is not registered, so"
                        + " AlgorithmParameters.CCM cannot come from the provider this"
                        + " cipher belongs to",
                e.getMessage());
    }

    /**
     * End to end through a directly-constructed SPI — the only route that
     * reaches the unbound arm. The refusal surfaces as the {@code
     * ProviderException} {@code engineGetParameters} is contracted to throw,
     * not as a parameters object from somewhere else.
     */
    @Test
    public void aDirectlyConstructedSpiFailsRatherThanResolvingElsewhere() throws Exception
    {
        AESCCMCipherSpi spi = new AESCCMCipherSpi();
        spi.engineInit(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), (java.security.SecureRandom) null);

        Assertions.assertNotNull(spi.engineGetParameters(),
                "control: with JSL registered the unbound SPI resolves by name");

        Provider jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Security.removeProvider(JostleProvider.PROVIDER_NAME);
        try
        {
            Assertions.assertNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                    "vacuity guard: JSL must actually be unregistered");

            ProviderException e = Assertions.assertThrows(ProviderException.class,
                    spi::engineGetParameters,
                    "an unbound SPI whose own provider is gone must fail loudly");
            Assertions.assertTrue(e.getCause() instanceof NoSuchAlgorithmException,
                    "and the cause must be the name resolution, not something else; was "
                            + e.getCause());
        }
        finally
        {
            Security.addProvider(jsl);
        }
    }
}
