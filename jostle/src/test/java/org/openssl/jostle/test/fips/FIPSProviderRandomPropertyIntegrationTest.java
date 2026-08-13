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
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.test.JvmProbe;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * Covers {@code org.openssl.jostle.fips.enforce_provider_random}, the escape hatch that lets
 * a provider-bound service honour a caller-supplied SecureRandom the provider-backed check
 * cannot recognise.
 * <p>
 * {@code FIPSAESKeyGeneratorTest} already pins the resolution logic for both values of the
 * flag, via the explicit-flag overload of
 * {@link CryptoServicesRegistrar#resolveProviderRandom(SecureRandom, SecureRandom, boolean)},
 * and the enforced end-to-end behaviour. What no test could reach from inside a running JVM
 * is the link between the two: the property is read once into a {@code static final} field
 * during class initialisation, so every existing test runs with it unset. A hardcoded
 * {@code true}, a typo in the property name, or the wrong default passed to
 * {@code isOverrideSet} would all pass that suite untouched.
 * <p>
 * These tests close that gap by launching a JVM with the property actually set. The FIPS
 * cases additionally prove the hatch does what it promises at the JCE surface, and are gated
 * on {@code TEST_FIPS_LIB}; the wiring test needs no module and always runs.
 */
public class FIPSProviderRandomPropertyIntegrationTest
{
    private static final String P_ENFORCE = "org.openssl.jostle.fips.enforce_provider_random";

    /**
     * The property reaches the static field. Needs no FIPS module - the accessor is a plain
     * read of the flag - so this runs everywhere and is the minimal proof that the two states
     * the other tests assume are actually reachable.
     */
    @Test
    public void enforceProviderRandom_propertyReachesTheStaticField() throws Exception
    {
        Assertions.assertEquals("true",
                runProbe(null).get("providerRandomEnforced"),
                "the default with the property unset must be enforced");

        Assertions.assertEquals("false",
                runProbe("false").get("providerRandomEnforced"),
                "setting the property false must disable enforcement");
    }

    /**
     * Only the exact string "true" counts as true, so an unrecognised value disables
     * enforcement rather than falling back to the default. Worth pinning: the failure mode is
     * silent and the safe-looking direction is the wrong one.
     */
    @Test
    public void enforceProviderRandom_nonBooleanValue_readsAsFalse() throws Exception
    {
        Assertions.assertEquals("false", runProbe("yes").get("providerRandomEnforced"));
    }

    /**
     * Enforced (the default): the caller's SHA1PRNG does not determine the key, so two
     * identically-seeded ones yield different keys. This is the control for the escape-hatch
     * test below - without it, that test could pass against an implementation that ignored
     * the caller random in both states.
     */
    @Test
    public void enforced_nonProviderRandomDoesNotDetermineKey() throws Exception
    {
        assumeFipsModule();

        long seed = new SecureRandom().nextLong();
        JvmProbe.Result probe = runProbe(null, seed);

        Assertions.assertEquals("true", probe.get("providerRandomEnforced"));
        Assertions.assertEquals("true", probe.get("fipsAvailable"));
        assertUsableKey(probe.get("key.0"));
        Assertions.assertNotEquals(probe.get("key.0"), probe.get("key.1"),
                "enforced, identically-seeded SHA1PRNGs must be overridden by the module DRBG "
                        + "(seed=" + seed + ")");
    }

    /**
     * The escape hatch itself: with enforcement off the caller's SecureRandom is honoured
     * verbatim, so the same two identically-seeded SHA1PRNGs now produce the SAME key. Paired
     * with the control above, this is what proves the property changes behaviour end to end
     * rather than merely flipping a flag nothing consults.
     */
    @Test
    public void notEnforced_nonProviderRandomDeterminesKey() throws Exception
    {
        assumeFipsModule();

        long seed = new SecureRandom().nextLong();
        JvmProbe.Result probe = runProbe("false", seed);

        Assertions.assertEquals("false", probe.get("providerRandomEnforced"));
        Assertions.assertEquals("true", probe.get("fipsAvailable"));
        assertUsableKey(probe.get("key.0"));
        Assertions.assertEquals(probe.get("key.0"), probe.get("key.1"),
                "with enforcement disabled the caller's SecureRandom must be honoured, so "
                        + "identically-seeded SHA1PRNGs must agree (seed=" + seed + ")");
    }

    private static void assumeFipsModule()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
    }

    /**
     * A real 256-bit key, not a zero-filled buffer that would compare equal to itself and
     * satisfy the escape-hatch assertion for the wrong reason.
     */
    private static void assertUsableKey(String hex)
    {
        Assertions.assertEquals(64, hex.length(), "expected a 256-bit key: " + hex);
        Assertions.assertFalse(hex.matches("0+"), "key must not be all zeroes");
    }

    private static JvmProbe.Result runProbe(String enforceValue) throws Exception
    {
        return runProbe(enforceValue, 0L);
    }

    private static JvmProbe.Result runProbe(String enforceValue, long seed) throws Exception
    {
        return JvmProbe.run(
                ProviderRandomProbeMain.class,
                enforceValue == null ? JvmProbe.props() : JvmProbe.props(P_ENFORCE, enforceValue),
                Long.toString(seed));
    }
}
