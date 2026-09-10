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

package org.openssl.jostle.test.provider;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.Provider;
import java.security.Security;

/**
 * A cipher bound to a provider INSTANCE resolves its parameters from that
 * instance and never falls back to the registry.
 *
 * <p>This is the property that cannot be observed any other way. Both providers
 * compute identical bytes, so no output distinguishes "resolved from my own
 * instance" from "resolved from whatever the registry offered" — the only
 * discriminator is an instance that is deliberately INCAPABLE while a capable
 * one sits registered under the name.
 *
 * <p>Without it, an accidental future fallback would be invisible on every
 * green run: the registered full provider would satisfy it silently, exactly as
 * BouncyCastle on the test classpath silently satisfied the ChaCha20
 * delegation that MT-18 found.
 */
public class BoundParameterResolutionTest
{
    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void aBoundCipherFailsLoudlyRatherThanBorrowingFromTheRegistry() throws Exception
    {
        // The full provider IS registered — that is the point. If resolution
        // leaked to the registry, this is what would quietly satisfy it.
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                "the capable provider must be registered, or the test proves nothing");
        Assertions.assertNotNull(
                AlgorithmParameters.getInstance("AES", JostleProvider.PROVIDER_NAME),
                "vacuity guard: the registry can serve AES parameters");

        Provider stripped = new StrippedJostleProvider("AlgorithmParameters", "AES");
        Assertions.assertNull(stripped.getService("AlgorithmParameters", "AES"),
                "vacuity guard: the strip must actually have removed the service");
        Assertions.assertNotNull(stripped.getService("Cipher", "AES"),
                "the stripped instance must still serve the cipher itself");

        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", stripped);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));

        Assertions.assertThrows(IllegalStateException.class, c::getParameters,
                "a cipher bound to an instance lacking the service must FAIL, not borrow"
                        + " the registered provider's copy");
    }

    /** The control: the same cipher from a FULL instance resolves normally. */
    @Test
    public void anUnstrippedInstanceResolvesItsOwnParameters() throws Exception
    {
        Provider full = new JostleProvider();
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding", full);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));

        AlgorithmParameters p = c.getParameters();
        Assertions.assertNotNull(p, "a capable instance must serve its own parameters");
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, p.getProvider().getName(),
                "and they must come from Jostle");
    }

    /**
     * CCM resolves its parameters from the SPI's own provider instance.
     *
     * <p>CCM had no instance path at all until MT-89 — it resolved by NAME
     * through {@code JostleAlgorithmParameters}, whose fallback hands the
     * OTHER Jostle provider's parameters to an unregistered instance. The
     * name path is retained only for a directly-constructed SPI.
     */
    @Test
    public void ccmOnAnUnregisteredInstanceResolvesItsOwnParameters() throws Exception
    {
        Provider unregistered = new JostleProvider();
        Assertions.assertNotSame(unregistered, Security.getProvider(JostleProvider.PROVIDER_NAME),
                "vacuity guard: the instance under test must not be the registered one");
        Assertions.assertNotNull(Security.getProvider(JostleProvider.PROVIDER_NAME),
                "the registered provider must be present, or nothing could be borrowed");

        Cipher c = Cipher.getInstance("AES/CCM/NoPadding", unregistered);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));

        AlgorithmParameters p = c.getParameters();
        Assertions.assertNotNull(p, "an unregistered instance must still serve its own parameters");
        Assertions.assertSame(unregistered, p.getProvider(),
                "CCM parameters must come from the SPI's own instance");
    }

    /** The registered path is unchanged. */
    @Test
    public void ccmThroughTheRegistryStillResolves() throws Exception
    {
        Cipher c = Cipher.getInstance("AES/CCM/NoPadding", JostleProvider.PROVIDER_NAME);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"));

        AlgorithmParameters p = c.getParameters();
        Assertions.assertNotNull(p, "the registered path must still serve parameters");
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, p.getProvider().getName(),
                "and they must come from Jostle");
        Assertions.assertNotNull(p.getParameterSpec(GCMParameterSpec.class),
                "and they must read back as the CCM nonce + ICV length");
    }
}
