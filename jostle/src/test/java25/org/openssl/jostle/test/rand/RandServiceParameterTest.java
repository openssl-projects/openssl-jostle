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

package org.openssl.jostle.test.rand;

import java.security.SecureRandom;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.rand.RandAlgorithm;
import org.openssl.jostle.util.Arrays;

import java.security.DrbgParameters;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.SecureRandomParameters;

public class RandServiceParameterTest
{
    @BeforeAll
    public static void beforeAll()
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    @Test
    public void drbgInstantiationParametersAreSupported() throws Exception
    {
        byte[] personalizationString = new byte[]{ 1, 2, 3 };
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED,
                        personalizationString),
                JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output);

        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, random.getProvider().getName());
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
    public void defaultAliasInstantiationParametersAreSupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DEFAULT",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null),
                JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output);

        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, random.getProvider().getName());
        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
        DrbgParameters.Instantiation params = (DrbgParameters.Instantiation) random.getParameters();
        Assertions.assertEquals(128, params.getStrength());
        Assertions.assertEquals(DrbgParameters.Capability.RESEED_ONLY, params.getCapability());
    }

    @Test
    public void drbgInstantiationDefaultStrengthUsesAlgorithmStrength() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(-1, DrbgParameters.Capability.NONE, null),
                JostleProvider.PROVIDER_NAME);

        DrbgParameters.Instantiation params = (DrbgParameters.Instantiation) random.getParameters();

        Assertions.assertEquals(RandAlgorithm.DRBG.getMaxStrength(), params.getStrength());
        Assertions.assertEquals(DrbgParameters.Capability.NONE, params.getCapability());
    }

    @Test
    public void drbgInstantiationRejectsInvalidStrength()
    {
        Assertions.assertThrows(IllegalArgumentException.class, () ->
                SecureRandom.getInstance("DRBG",
                        DrbgParameters.instantiation(-2, DrbgParameters.Capability.NONE, null),
                        JostleProvider.PROVIDER_NAME));
    }

    @Test
    public void drbgInstantiationRejectsUnsupportedParameters()
    {
        Assertions.assertThrows(NoSuchAlgorithmException.class, () ->
                SecureRandom.getInstance("DRBG", unsupportedParameters(),
                        JostleProvider.PROVIDER_NAME));
    }

    @Test
    public void drbgInstantiationSupportsPersonalizationString() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.NONE, new byte[1]),
                JostleProvider.PROVIDER_NAME);

        Assertions.assertEquals(JostleProvider.PROVIDER_NAME, random.getProvider().getName());
    }

    @Test
    public void nextBytesParametersAreSupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output, DrbgParameters.nextBytes(128, false, null));

        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
    }

    @Test
    public void nextBytesDefaultStrengthParametersAreSupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output, DrbgParameters.nextBytes(-1, false, null));

        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
    }

    @Test
    public void nextBytesDefaultStrengthUsesInstanceStrength() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null),
                JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output, DrbgParameters.nextBytes(-1, false, null));

        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
    }

    @Test
    public void nextBytesRejectsStrengthAboveInstanceStrength() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null),
                JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.nextBytes(new byte[16], DrbgParameters.nextBytes(256, false, null)));
    }

    @Test
    public void nextBytesRejectsInvalidStrength() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.nextBytes(new byte[16], DrbgParameters.nextBytes(-2, false, null)));
    }

    @Test
    public void nextBytesRejectsNullParameters() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.nextBytes(new byte[16], null));
    }

    @Test
    public void nextBytesRejectsNullBytesWithParameters() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(NullPointerException.class, () ->
                random.nextBytes(null, DrbgParameters.nextBytes(128, false, null)));
    }

    @Test
    public void nextBytesRejectsUnsupportedParameters() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.nextBytes(new byte[16], unsupportedParameters()));
    }

    @Test
    public void nextBytesSupportsAdditionalInput() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output, DrbgParameters.nextBytes(128, false, new byte[1]));

        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
    }

    @Test
    public void nextBytesRejectsPredictionResistanceWithoutCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.nextBytes(new byte[16], DrbgParameters.nextBytes(128, true, null)));
    }

    @Test
    public void nextBytesPredictionResistanceIsSupportedWithCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED, null),
                JostleProvider.PROVIDER_NAME);
        byte[] output = new byte[16];

        random.nextBytes(output, DrbgParameters.nextBytes(128, true, null));

        Assertions.assertFalse(Arrays.areEqual(new byte[output.length], output));
    }

    @Test
    public void reseedParametersAreSupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        random.reseed(DrbgParameters.reseed(false, null));
    }

    @Test
    public void reseedNoParametersIsSupported() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        random.reseed();
    }

    @Test
    public void reseedNoParametersSupportsPredictionResistanceCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED, null),
                JostleProvider.PROVIDER_NAME);

        random.reseed();
    }

    @Test
    public void reseedRejectsCapabilityNone() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.NONE, null),
                JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.reseed(DrbgParameters.reseed(false, null)));
    }

    @Test
    public void reseedRejectsPredictionResistanceWithoutCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(IllegalArgumentException.class, () ->
                random.reseed(DrbgParameters.reseed(true, null)));
    }

    @Test
    public void reseedRejectsUnsupportedParameters() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        Assertions.assertThrows(UnsupportedOperationException.class, () ->
                random.reseed(unsupportedParameters()));
    }

    @Test
    public void reseedPredictionResistanceIsSupportedWithCapability() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED, null),
                JostleProvider.PROVIDER_NAME);

        random.reseed(DrbgParameters.reseed(true, null));
    }

    @Test
    public void reseedSupportsAdditionalInput() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);

        random.reseed(DrbgParameters.reseed(false, new byte[1]));
    }

    @Test
    public void setSeedSupplementsParameterizedInstance() throws Exception
    {
        SecureRandom random = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.NONE, null),
                JostleProvider.PROVIDER_NAME);

        random.setSeed(new byte[]{ 1, 2, 3, 4 });
        random.nextBytes(new byte[16]);
    }

    @Test
    public void nextBytesWithParametersProducesDifferentOutputAcrossCalls() throws Exception
    {
        // Two parameterized draws from one instance must differ — guards against
        // a stub that returns a fixed (non-zero) buffer.
        SecureRandom random = SecureRandom.getInstance("DRBG", JostleProvider.PROVIDER_NAME);
        byte[] first = new byte[32];
        byte[] second = new byte[32];

        random.nextBytes(first, DrbgParameters.nextBytes(128, false, null));
        random.nextBytes(second, DrbgParameters.nextBytes(128, false, null));

        Assertions.assertFalse(Arrays.areEqual(first, second));
    }

    @Test
    public void independentParameterizedInstancesProduceDifferentStreams() throws Exception
    {
        // Identical instantiation parameters: the streams must still differ
        // because each context is seeded from the OS-seeded parent DRBG.
        byte[] personalizationString = new byte[]{ 1, 2, 3 };
        SecureRandom first = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED, personalizationString),
                JostleProvider.PROVIDER_NAME);
        SecureRandom second = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(128, DrbgParameters.Capability.PR_AND_RESEED, personalizationString),
                JostleProvider.PROVIDER_NAME);
        byte[] firstOutput = new byte[32];
        byte[] secondOutput = new byte[32];

        first.nextBytes(firstOutput);
        second.nextBytes(secondOutput);

        Assertions.assertFalse(Arrays.areEqual(firstOutput, secondOutput));
    }

    private static SecureRandomParameters unsupportedParameters()
    {
        return new SecureRandomParameters()
        {
        };
    }
}
