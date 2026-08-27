/*
 *  Copyright 2026 OpenSSL Jostle Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License"). You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://github.com/openssl-projects/openssl-jostle/blob/main/LICENSE
 *
 */

package org.openssl.jostle.test.spec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.interfaces.OSSLKey;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.spec.PKEYKeySpec;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;

/**
 * MT-14's binding mechanism, under test BEFORE it is activated.
 *
 * <p>{@code FIPSCrossInstanceKeyTest} self-arms and therefore skips through
 * Phase 1, which would otherwise leave {@code PKEYKeySpec.usableBy} — the
 * decision every acceptance point delegates to — with no coverage at all until
 * the flip. This file is green in both phases and pins the four cells
 * directly, so the mechanism is verified before anything depends on it.
 *
 * <p>The four cells are a DEFINED contract, not a consequence of a null
 * comparison. In particular {@code unbound x unbound} accepts on purpose:
 * refusing it would break every direct-SPI consumer, since a KeyPairGenerator
 * constructed outside any provider would produce keys its own sibling SPIs
 * reject. The unbound realm has no provider boundary to protect.
 */
public class KeySpecBindingTest
{
    private static Provider jsl;

    @BeforeAll
    static void before()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
    }

    private static PKEYKeySpec freshSpec() throws Exception
    {
        KeyPair kp = KeyPairGenerator.getInstance("ML-KEM-768",
                JostleProvider.PROVIDER_NAME).generateKeyPair();
        return ((OSSLKey) kp.getPublic()).getSpec();
    }

    /**
     * unbound x unbound accepts — the cell that keeps direct-SPI construction
     * working, and the one most likely to be "fixed" into a refusal by someone
     * reading the others.
     */
    @Test
    public void unboundSpecIsUsableByAnUnboundCaller() throws Exception
    {
        PKEYKeySpec spec = freshSpec();
        Assertions.assertNull(spec.getProviderInstance(),
                "Phase 1: registrations do not bind yet, so this spec must be unbound. "
                        + "If this fails, Phase 2 has landed and this test needs revisiting.");
        Assertions.assertTrue(spec.usableBy(null),
                "an unbound spec must be usable by an unbound caller — otherwise every "
                        + "direct-SPI consumer breaks");
    }

    /**
     * bound x unbound and unbound x bound both refuse. Fail closed in both
     * directions: an unbound key is never silently adopted by a provider, and
     * a provider's key is never handed to something with no identity.
     */
    @Test
    public void bindingMismatchRefusesInBothDirections() throws Exception
    {
        PKEYKeySpec unbound = freshSpec();
        Assertions.assertFalse(unbound.usableBy(jsl),
                "an unbound spec must NOT be adopted by a provider instance");

        PKEYKeySpec bound = boundSpec(jsl);
        Assertions.assertFalse(bound.usableBy(null),
                "a bound spec must NOT be usable by an unbound caller");
    }

    /**
     * bound x bound: same instance accepts, different instances refuse. This
     * is the whole point of MT-14, and it is testable now because a second
     * JostleProvider instance is constructible whether or not it is
     * registered — {@code getInstance(alg, Provider)} does not require
     * registration, which is exactly why name-level identity is insufficient.
     */
    @Test
    public void sameInstanceAcceptsDifferentInstanceRefuses() throws Exception
    {
        Provider other = new JostleProvider();
        Assertions.assertNotSame(jsl, other, "a second instance must be a distinct object");

        PKEYKeySpec bound = boundSpec(jsl);
        Assertions.assertTrue(bound.usableBy(jsl), "same instance must be accepted");
        Assertions.assertFalse(bound.usableBy(other),
                "a DIFFERENT instance of the same provider class must be refused — name-level "
                        + "identity cannot express this, which is why binding is by reference");
    }

    /**
     * A spec bound to {@code p}, over a FRESHLY ALLOCATED native reference
     * that nothing else owns.
     *
     * <p>Deliberately not built by re-wrapping an existing key's reference:
     * that would put two {@code PKEYReference} disposers on one native handle
     * and double-free it when both are collected — an intermittent crash in
     * the test suite, which is the worst kind. {@code allocate()} hands back a
     * reference owned solely by the spec built over it, the same shape the
     * KeyFactories use.
     *
     * <p>The spec has no KEY, which is fine: {@code usableBy} is a comparison
     * of provider references and never touches the native key.
     */
    private static PKEYKeySpec boundSpec(Provider p)
    {
        org.openssl.jostle.jcajce.spec.SpecNI specNI =
                org.openssl.jostle.test.crypto.TestNISelector.getSpecNI();
        return new PKEYKeySpec(specNI, specNI.allocate(),
                org.openssl.jostle.jcajce.spec.OSSLKeyType.ML_KEM_768, p);
    }
}
