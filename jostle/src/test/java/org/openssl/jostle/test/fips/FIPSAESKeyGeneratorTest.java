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
import org.openssl.jostle.CryptoServicesRegistrar;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.util.Arrays;

import javax.crypto.KeyGenerator;
import java.security.SecureRandom;

/**
 * Behaviour-lock unit tests for the FIPS provider's AES {@link KeyGenerator}
 * surface. This is the FIPS analogue of
 * {@code crypto/AESKeyGeneratorTest}; it mirrors that test's assertion
 * structure and exact messages, changing only the provider (JSLFIPS), the
 * gating, and the key origin.
 * <p>
 * The bare {@code "AES"} generator defaults to 256 bits; {@code "AES128"},
 * {@code "AES192"} and {@code "AES256"} are fixed-size primaries that reject a
 * mismatched caller override. Every generated key is asserted non-zero, which
 * proves the FIPS KeyGenerator is drawing from the module's own approved DRBG
 * ({@code provider.getDefaultSecureRandom()}) rather than being mis-wired to a
 * null/JDK random or the wrong default. Because the key bytes are drawn in
 * Java, the generator enforces (by default) the provider-backed SecureRandom
 * check in {@link CryptoServicesRegistrar#resolveProviderRandom}: a
 * caller-supplied SecureRandom that is NOT backed by the FIPS provider is
 * overridden by the module DRBG, so {@code KeyGenerator.init(int)}'s
 * JCE-injected JVM default cannot pull key bytes outside the FIPS boundary. A
 * same-provider SecureRandom is still honoured, and the check is disabled via
 * {@link CryptoServicesRegistrar#ENFORCE_PROVIDER_RANDOM}.
 * <p>
 * Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSAESKeyGeneratorTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;

    /**
     * Class-level gate: the whole class skips when TEST_FIPS_LIB is unset.
     * Gating here rather than per test method fails closed, so a test added
     * later is gated automatically.
     */
    @BeforeAll
    static void before()
    {
        ensureProviders();
    }

    private static void ensureProviders()
    {
        FIPSTestUtil.assumeFipsProvider();
    }

    @Test
    public void keyGenInvalidSizeRejected() throws Exception
    {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", FIPS);
        for (int size : new int[]{0, 127, 129, 191, 193, 255, 257})
        {
            try
            {
                keyGen.init(size, new SecureRandom());
                Assertions.fail("Should have thrown an exception");
            } catch (IllegalArgumentException ila)
            {
                Assertions.assertEquals("key size must be 128, 192 or 256", ila.getMessage());
            }
        }
    }

    @Test
    public void keyGenFixedSizeMismatchRejected() throws Exception
    {
        SecureRandom sr = new SecureRandom();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES128", FIPS);
        try
        {
            keyGen.init(192, sr);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 128", iae.getMessage());
        }

        keyGen = KeyGenerator.getInstance("AES192", FIPS);
        try
        {
            keyGen.init(256, sr);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 192", iae.getMessage());
        }

        keyGen = KeyGenerator.getInstance("AES256", FIPS);
        try
        {
            keyGen.init(128, sr);
            Assertions.fail("Should have thrown an exception");
        } catch (IllegalArgumentException iae)
        {
            Assertions.assertEquals("key size must be 256", iae.getMessage());
        }
    }

    @Test
    public void keyGenDefault256AndNonZeroFromModuleDrbg() throws Exception
    {
        // Bare "AES" defaults to 256 bits without an explicit init().
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", FIPS);
        byte[] keyBytes = keyGen.generateKey().getEncoded();
        Assertions.assertEquals(256, keyBytes.length << 3);
        Assertions.assertFalse(Arrays.areAllZeroes(keyBytes, 0, keyBytes.length));

        // Fixed-size primaries yield their size without an explicit init().
        for (String algorithm : new String[]{"AES128", "AES192", "AES256"})
        {
            KeyGenerator fixed = KeyGenerator.getInstance(algorithm, FIPS);
            byte[] fixedBytes = fixed.generateKey().getEncoded();
            int expectedSize = Integer.parseInt(algorithm.substring("AES".length()));

            Assertions.assertEquals(expectedSize, fixedBytes.length << 3);
            Assertions.assertFalse(Arrays.areAllZeroes(fixedBytes, 0, fixedBytes.length));
        }

        // The explicitly-init'd valid sizes on the bare "AES" generator.
        for (int size : new int[]{128, 192, 256})
        {
            keyGen.init(size, new SecureRandom());
            byte[] sizedBytes = keyGen.generateKey().getEncoded();
            Assertions.assertEquals(size, sizedBytes.length << 3);
            Assertions.assertFalse(Arrays.areAllZeroes(sizedBytes, 0, sizedBytes.length));
        }
    }

    /**
     * Pins the provider-backed SecureRandom resolution the FIPS AES keygen
     * relies on ({@link CryptoServicesRegistrar#resolveProviderRandom}), using a
     * JSLFIPS SecureRandom as the provider-backed source and SHA1PRNG (SUN) as
     * the outsider. Return-identity makes every branch deterministic.
     */
    @Test
    public void resolveProviderRandom_prefersModuleDrbgOverNonProviderRandom() throws Exception
    {
        SecureRandom moduleDrbg = SecureRandom.getInstance("DEFAULT", FIPS);
        SecureRandom fipsBacked = SecureRandom.getInstance("DEFAULT", FIPS);
        SecureRandom nonFips = SecureRandom.getInstance("SHA1PRNG");

        // Precondition: these really do differ by backing provider.
        Assertions.assertSame(moduleDrbg.getProvider(), fipsBacked.getProvider());
        Assertions.assertNotSame(moduleDrbg.getProvider(), nonFips.getProvider());

        // Enforced (default): a non-provider random is overridden by the module
        // DRBG; a same-provider random and the null case use the module DRBG.
        Assertions.assertSame(moduleDrbg,
                CryptoServicesRegistrar.resolveProviderRandom(nonFips, moduleDrbg));
        Assertions.assertSame(fipsBacked,
                CryptoServicesRegistrar.resolveProviderRandom(fipsBacked, moduleDrbg));
        Assertions.assertSame(moduleDrbg,
                CryptoServicesRegistrar.resolveProviderRandom(null, moduleDrbg));

        // Not provider-bound (the non-FIPS generator passes null here): standard
        // JCE resolution — the caller's random is honoured.
        Assertions.assertSame(nonFips,
                CryptoServicesRegistrar.resolveProviderRandom(nonFips, null));

        // Explicit flag: off honours the caller verbatim (the escape hatch); on
        // overrides. The static default must be enforced (property unset).
        Assertions.assertSame(nonFips,
                CryptoServicesRegistrar.resolveProviderRandom(nonFips, moduleDrbg, false));
        Assertions.assertSame(moduleDrbg,
                CryptoServicesRegistrar.resolveProviderRandom(nonFips, moduleDrbg, true));
        Assertions.assertTrue(CryptoServicesRegistrar.isProviderRandomEnforced());
    }

    /**
     * End-to-end: with the check enforced (default), initialising the FIPS AES
     * KeyGenerator with a non-provider SecureRandom (SHA1PRNG) does NOT let that
     * random determine the key — the module DRBG is used instead. Two
     * identically-seeded SHA1PRNGs therefore produce DIFFERENT keys; they would
     * be identical if the caller random were honoured (as it is in the non-FIPS
     * provider). This is the fix for {@code KeyGenerator.init(int)} silently
     * pulling AES key bytes from the JVM default SecureRandom outside the FIPS
     * boundary.
     */
    @Test
    public void nonProviderCallerRandom_doesNotDetermineKey() throws Exception
    {
        Assertions.assertTrue(CryptoServicesRegistrar.isProviderRandomEnforced(),
                "test assumes the default (enforced) policy");

        long seed = new SecureRandom().nextLong();
        byte[] first = generateKeyWithSeededRandom(seed);
        byte[] second = generateKeyWithSeededRandom(seed);

        Assertions.assertEquals(256, first.length << 3);
        Assertions.assertFalse(Arrays.areAllZeroes(first, 0, first.length));
        Assertions.assertFalse(Arrays.areEqual(first, second),
                "a non-provider SecureRandom must not determine FIPS AES key bytes; the "
                        + "identically-seeded SHA1PRNGs should have been overridden by the module "
                        + "DRBG (seed=" + seed + ")");
    }

    private static byte[] generateKeyWithSeededRandom(long seed) throws Exception
    {
        SecureRandom seeded = SecureRandom.getInstance("SHA1PRNG");
        seeded.setSeed(seed);
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", FIPS);
        keyGen.init(256, seeded);
        return keyGen.generateKey().getEncoded();
    }
}
