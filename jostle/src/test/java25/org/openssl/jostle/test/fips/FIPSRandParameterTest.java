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

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SecureRandomParameters;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

/**
 * Parameter-driven DRBG state-machine <b>behaviour</b> through the FIPS provider
 * ("JSLFIPS"). Mirrors {@code RandServiceParameterTest} (non-FIPS) but resolves
 * every {@link SecureRandom} through {@code JSLFIPS} and restricts variant
 * coverage to the FIPS-approved DRBG set (no truncated SHA-224/384 digests — see
 * {@code ProvFIPSRand.APPROVED_DRBG_DIGESTS}).
 *
 * <p>The rejection cases assert exception <b>type</b> only: these exceptions are
 * thrown by the JDK {@code SecureRandom}/DRBG framework, whose messages vary
 * across JDK releases (testing.md exempts JDK-provider-thrown messages from the
 * pin-the-message rule). Gated on TEST_FIPS_LIB; skipped when unset.
 */
public class FIPSRandParameterTest
{
    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    @Test
    public void drbgInstantiationParametersRoundTripThroughGetParameters() throws Exception
    {
        byte[] personalizationString = new byte[16];
        RANDOM.nextBytes(personalizationString);

        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED,
                        personalizationString),
                JostleFIPSProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output);

        Assertions.assertEquals(JostleFIPSProvider.PROVIDER_NAME, random.getProvider().getName());
        Assertions.assertEquals("DRBG", random.getAlgorithm());
        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));

        SecureRandomParameters params = random.getParameters();
        Assertions.assertTrue(params instanceof DrbgParameters.Instantiation);
        DrbgParameters.Instantiation instantiation = (DrbgParameters.Instantiation) params;
        Assertions.assertEquals(128, instantiation.getStrength());
        Assertions.assertEquals(DrbgParameters.Capability.PR_AND_RESEED, instantiation.getCapability());
        Assertions.assertTrue(Arrays.areEqual(personalizationString, instantiation.getPersonalizationString()));
    }

    @Test
    public void drbgInstantiationRejectsUnsupportedParameters()
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class, () ->
                SecureRandom.getInstance("DRBG", unsupportedParameters(),
                        JostleFIPSProvider.PROVIDER_NAME));
    }

    @Test
    public void nextBytesRejectsUnsupportedParameters() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleFIPSProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.nextBytes(new byte[16], unsupportedParameters()));
    }

    @Test
    public void reseedRejectsCapabilityNone() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.NONE, null),
                JostleFIPSProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.reseed(DrbgParameters.reseed(false, null)));
    }

    @Test
    public void nextBytesRejectsPredictionResistanceWithoutCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleFIPSProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.nextBytes(new byte[16], DrbgParameters.nextBytes(128, true, null)));
    }

    @Test
    public void reseedRejectsPredictionResistanceWithoutCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleFIPSProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.reseed(DrbgParameters.reseed(true, null)));
    }

    @Test
    public void perApprovedVariantStrengthCeilingEnforced() throws Exception
    {
        // For each FIPS-approved variant: a request AT the variant's strength
        // ceiling is accepted and usable, and one ABOVE it is rejected. The
        // truncated-digest variants (SHA-224/384) are intentionally excluded —
        // they are not registered by the FIPS provider.
        assertStrengthCeiling("CTR-DRBG-AES128", 128);
        assertStrengthCeiling("CTR-DRBG-AES192", 192);
        assertStrengthCeiling("CTR-DRBG-AES256", 256);
        assertStrengthCeiling("HASH-DRBG-SHA1", 128);
        assertStrengthCeiling("HASH-DRBG-SHA256", 256);
        assertStrengthCeiling("HASH-DRBG-SHA512", 256);
        assertStrengthCeiling("HMAC-DRBG-SHA1", 128);
        assertStrengthCeiling("HMAC-DRBG-SHA512", 256);
    }

    private static void assertStrengthCeiling(String algorithm, int ceiling) throws Exception
    {
        // At the ceiling: accepted and usable.
        SecureRandom accepted = SecureRandom.getInstance(algorithm,
                DrbgParameters.instantiation(ceiling, DrbgParameters.Capability.NONE, null),
                JostleFIPSProvider.PROVIDER_NAME);
        byte[] out = new byte[16];
        accepted.nextBytes(out);
        Assertions.assertFalse(Arrays.areEqual(new byte[out.length], out), algorithm);

        // One above the ceiling: rejected. getInstance wraps the SPI's
        // IllegalArgumentException in NoSuchAlgorithmException, so unwrap.
        Throwable thrown = Assertions.assertThrows(Throwable.class, () ->
                SecureRandom.getInstance(algorithm,
                        DrbgParameters.instantiation(ceiling + 1, DrbgParameters.Capability.NONE, null),
                        JostleFIPSProvider.PROVIDER_NAME));
        Throwable root = thrown;
        while (root.getCause() != null)
        {
            root = root.getCause();
        }
        Assertions.assertTrue(root instanceof IllegalArgumentException,
                algorithm + ": expected IllegalArgumentException root cause, got " + root);
    }

    private static SecureRandomParameters unsupportedParameters()
    {
        return new SecureRandomParameters()
        {
        };
    }
}
