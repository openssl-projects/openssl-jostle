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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * Behaviour lock proving that the {@link InvalidKeyException} the JSLFIPS
 * operational SPIs throw for a foreign (JSL-bound) private key genuinely
 * drives the JCE {@code Provider[]} traversal - i.e. a provider-less
 * {@code Signature.getInstance("SHA256withRSA")} that hands JSLFIPS a key it
 * must reject actually FALLS THROUGH to the next installed provider and
 * completes there.
 * <p>
 * This is the end-to-end complement to {@link FIPSKeyIsolationTest}, which
 * asserts the rejection type/message when the provider is named explicitly.
 * The isolation tests would stay green even if the rejection regressed to a
 * {@link java.security.ProviderException} (a {@code RuntimeException}) - but
 * that regression silently breaks JCE fallback, because only
 * {@code InvalidKeyException} / {@code InvalidAlgorithmParameterException}
 * cause the JCA delegate to retry the next provider. This test locks the
 * fallback itself.
 * <p>
 * The provider list is reordered to put JSLFIPS ahead of JSL for the duration
 * of each test and restored to its exact prior order in {@link #tearDown()}.
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSProviderFallbackTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    private Provider[] savedProviders;

    @BeforeEach
    public void snapshotProviders()
    {
        // Snapshot the pristine provider order BEFORE any test reorders it or
        // adds the FIPS/JSL providers, so tearDown restores exactly this.
        savedProviders = Security.getProviders();
    }

    @AfterEach
    public void tearDown()
    {
        if (savedProviders == null)
        {
            return;
        }

        // Remove everything currently installed, then re-add the snapshot in
        // order - insertProviderAt cannot reposition an already-installed
        // provider, so a full rebuild is the only way to restore exact order.
        for (Provider p : Security.getProviders())
        {
            Security.removeProvider(p.getName());
        }
        for (Provider p : savedProviders)
        {
            Security.addProvider(p);
        }
    }

    /**
     * Force JSLFIPS to position 1 and JSL to position 2 in the provider
     * preference order, returning the resolved provider instances. Both must
     * already be constructable; JSLFIPS is established by
     * {@link FIPSTestUtil#assumeFipsProvider()} (which also applies the
     * TEST_FIPS_LIB skip guard) and JSL is added if absent.
     */
    private static void installFipsAheadOfJsl()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }

        Provider fipsProv = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        Provider jslProv = Security.getProvider(JostleProvider.PROVIDER_NAME);

        // Remove then re-insert at fixed ranks so JSLFIPS is tried first and
        // JSL is the immediate fallback target.
        Security.removeProvider(fipsProv.getName());
        Security.removeProvider(jslProv.getName());
        Security.insertProviderAt(fipsProv, 1);
        Security.insertProviderAt(jslProv, 2);
    }

    /**
     * With JSLFIPS installed ahead of JSL, a provider-less
     * {@code Signature.getInstance("SHA256withRSA")} whose {@code initSign} is
     * handed a JSL-bound private key must NOT fail: JSLFIPS rejects the
     * foreign key with a fallback-eligible {@link InvalidKeyException}, the
     * JCA delegate moves on to JSL, and the whole sign/verify round-trip
     * completes. The chosen provider is asserted to be JSL - direct proof that
     * traversal skipped JSLFIPS rather than the operation happening to work.
     */
    @Test
    public void invalidKeyExceptionFromJslfipsTriggersNextProviderFallback()
        throws Exception
    {
        installFipsAheadOfJsl();

        // A JSL-bound private key: the FIPS SPI must reject it (foreign to the
        // FIPS OSSL_LIB_CTX), while JSL - next in line - accepts its own key.
        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();

        byte[] message = new byte[64];
        RANDOM.nextBytes(message);

        // No provider argument: the JCA delegate walks the Provider[] in order.
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(jslKp.getPrivate());
        signer.update(message);
        byte[] sig = signer.sign();

        // The operation completed via fallback: JSLFIPS (rank 1) rejected the
        // key and traversal landed on JSL (rank 2). If the rejection had been
        // a ProviderException, this would have thrown instead of falling back.
        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, signer.getProvider().getName(),
                "provider-less Signature must fall back past JSLFIPS to JSL");

        // And the signature the fallback produced is valid.
        Signature verifier = Signature.getInstance("SHA256withRSA", JostleProvider.PROVIDER_NAME);
        verifier.initVerify(jslKp.getPublic());
        verifier.update(message);
        Assertions.assertTrue(verifier.verify(sig), "fallback-produced signature must verify");
    }

    /**
     * The weaker-but-load-bearing invariant the fallback depends on, locked
     * directly: when JSLFIPS is named explicitly and handed a foreign
     * (JSL-bound) private key, {@code initSign} throws the fallback-eligible
     * {@link InvalidKeyException} (with the canonical isolation message) and
     * NOT a {@link java.security.ProviderException}. A regression to a
     * RuntimeException here is exactly what would break the traversal locked
     * by {@link #invalidKeyExceptionFromJslfipsTriggersNextProviderFallback()}
     * while leaving the family isolation tests green.
     */
    @Test
    public void jslfipsRejectsForeignKeyWithFallbackEligibleType()
        throws Exception
    {
        installFipsAheadOfJsl();

        KeyPairGenerator jslKpg = KeyPairGenerator.getInstance("RSA", JostleProvider.PROVIDER_NAME);
        jslKpg.initialize(2048);
        KeyPair jslKp = jslKpg.generateKeyPair();

        Signature fipsSigner = Signature.getInstance("SHA256withRSA", JostleFIPSProvider.PROVIDER_NAME);
        InvalidKeyException e = Assertions.assertThrows(InvalidKeyException.class,
                () -> fipsSigner.initSign(jslKp.getPrivate()));
        Assertions.assertTrue(e.getMessage().contains("different Jostle provider"),
                "expected the isolation message, got: " + e.getMessage());
    }
}
