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
 * MT-14's binding mechanism: the four cells of {@code PKEYKeySpec.usableBy},
 * pinned directly rather than through the surfaces that delegate to it.
 *
 * <p>Written during Phase 1 so the decision every acceptance point relies on
 * had coverage before anything depended on it, and kept afterwards because it
 * is the only place the cells are stated as a contract. It is green in both
 * phases; what changed at the flip is only how each side is BUILT.
 *
 * <p><b>Where an unbound spec comes from after the flip.</b> Every registered
 * service now binds, so {@code KeyPairGenerator.getInstance(alg, "JSL")} no
 * longer yields one — {@link #unboundSpec()} constructs the SPI directly
 * instead, which is exactly the realm the unbound cells exist to protect. A
 * key from a registered provider is the BOUND side, and this file builds both
 * deliberately rather than letting either fall out of a default.
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

    /**
     * A spec from a KeyPairGenerator constructed OUTSIDE any provider, so it
     * carries no provider instance.
     *
     * <p>Deliberately not {@code KeyPairGenerator.getInstance(alg, "JSL")}:
     * since Phase 2 every registered service binds its keys, so that route
     * yields a BOUND spec and the three cells below would silently test the
     * wrong thing. Direct SPI construction is the supported way to work
     * outside a provider, and is the realm the unbound cells protect.
     */
    private static PKEYKeySpec unboundSpec() throws Exception
    {
        KeyPair kp = new org.openssl.jostle.jcajce.provider.mlkem.MLKEMKeyPairGenerator(
                "ML-KEM-768").generateKeyPair();
        return ((OSSLKey) kp.getPublic()).getSpec();
    }

    /**
     * A spec from the REGISTERED provider, which since Phase 2 binds every key
     * it produces. Distinct from {@link #boundSpec(Provider)} below, which
     * builds one by hand: this proves the registration path really does bind,
     * so the bound half of each cell is not an artefact of the test's own
     * construction.
     */
    private static PKEYKeySpec registeredSpec() throws Exception
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
        PKEYKeySpec spec = unboundSpec();
        Assertions.assertNull(spec.getProviderInstance(),
                "a KeyPairGenerator constructed outside any provider must produce unbound "
                        + "keys — if this fails, direct-SPI use has acquired an identity from "
                        + "somewhere and the unbound realm no longer exists");
        Assertions.assertTrue(spec.usableBy(null),
                "an unbound spec must be usable by an unbound caller — otherwise every "
                        + "direct-SPI consumer breaks");
    }

    /**
     * The flip itself: a key from a REGISTERED service carries that service's
     * provider instance. Nothing else in this file would notice if
     * registrations stopped binding — every other cell builds its bound spec
     * by hand — so this is the assertion that ties the mechanism to the
     * behaviour.
     */
    @Test
    public void aRegisteredProvidersKeysAreBoundToIt() throws Exception
    {
        PKEYKeySpec spec = registeredSpec();
        Assertions.assertSame(jsl, spec.getProviderInstance(),
                "a key generated through the registered provider must be bound to that "
                        + "provider INSTANCE");
        Assertions.assertTrue(spec.usableBy(jsl));
        Assertions.assertFalse(spec.usableBy(null));
    }

    /**
     * bound x unbound and unbound x bound both refuse. Fail closed in both
     * directions: an unbound key is never silently adopted by a provider, and
     * a provider's key is never handed to something with no identity.
     */
    @Test
    public void bindingMismatchRefusesInBothDirections() throws Exception
    {
        PKEYKeySpec unbound = unboundSpec();
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
