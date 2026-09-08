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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.rand.DefaultRandSource;

import java.security.DrbgParameters;
import java.security.DrbgParameters.Capability;
import java.security.SecureRandom;
import java.security.Security;

/**
 * MT-69, the positive half: the fix must not make the provider blind to
 * parameters a well-formed {@code SecureRandom} actually reports.
 *
 * <p>{@code parametersOrNull} swallows a failure from {@code getParameters()}
 * and returns null, which is the tolerated "no parameters" path. A plausible
 * but wrong implementation — returning null unconditionally, or catching too
 * broadly around more than the one call — would satisfy the negative half in
 * {@code SpiLessSecureRandomTest} perfectly while silently discarding real
 * {@link DrbgParameters}. This asserts the discarding does not happen.
 *
 * <h2>Why this is in java25 and its sibling is not</h2>
 *
 * <p>{@link DrbgParameters} and {@code SecureRandom.getParameters()} are both
 * {@code @since 9}, and {@code src/test/java} compiles at
 * {@code options.release = 8}. So this assertion cannot live beside the
 * negative half — which needs no Java 9+ API and therefore runs on every leg,
 * including the base leg that loads the java8 baseline. Each assertion sits on
 * the widest set of legs that can compile it.
 */
public class SpiLessSecureRandomParamsTest
{
    private static SecureRandom drbg;

    @BeforeAll
    public static void setUp() throws Exception
    {
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        drbg = SecureRandom.getInstance("DRBG",
                DrbgParameters.instantiation(256, Capability.RESEED_ONLY, null));
        System.out.println("[MT-69] DefaultRandSource code source="
                + DefaultRandSource.class.getProtectionDomain().getCodeSource().getLocation());
        System.out.flush();
    }

    /**
     * A real {@code DrbgParameters.Instantiation} is still read, so the fix
     * routed only the failing case to null.
     */
    @Test
    public void realDrbgParametersAreStillHonoured()
    {
        Assertions.assertTrue(drbg.getParameters() instanceof DrbgParameters.Instantiation,
                "precondition: the JDK DRBG must report a DrbgParameters.Instantiation,"
                        + " else this test cannot tell a working fix from a blind one");

        Assertions.assertEquals(256, DefaultRandSource.strengthOf(drbg),
                "strengthOf must still read the reported strength; 0 here would mean the"
                        + " fix discards real parameters, which the Spi-less test cannot see");
    }

    /**
     * The CONSTRUCTOR site, asserted separately from {@code strengthOf}.
     *
     * <p>The fix touches two call sites and they are independently mutable.
     * {@code realDrbgParametersAreStillHonoured} covers the helper itself, so it
     * fails if {@code parametersOrNull} were changed to return null
     * unconditionally — but it passes untouched if the CONSTRUCTOR were changed
     * to pass a literal null while the helper stayed correct. That mutation
     * silently drops {@code assertConditions}, leaving strength 0 and no
     * prediction-resistance assertion for a caller who supplied a real DRBG:
     * a security-relevant degradation with no caller-visible error.
     */
    @Test
    public void theConstructorStillReadsRealParameters()
    {
        Assertions.assertEquals(256, DefaultRandSource.wrap(drbg).getStrength(),
                "wrap() must carry the DRBG's reported strength through the constructor;"
                        + " 0 here means the constructor discarded real parameters");
    }

    /**
     * The discriminator: a random with NO parameters must report 0, so a
     * strengthOf that returned a constant would fail one of these two.
     */
    @Test
    public void aRandomWithNoParametersStillReportsZero() throws Exception
    {
        SecureRandom plain = SecureRandom.getInstance("SHA1PRNG");
        Assertions.assertNull(plain.getParameters(),
                "precondition: SHA1PRNG reports no parameters");
        Assertions.assertEquals(0, DefaultRandSource.strengthOf(plain),
                "a random reporting no parameters must yield strength 0");

        // Same discriminator for the constructor site, so a wrap() that
        // returned a constant strength fails here rather than passing both.
        Assertions.assertEquals(0, DefaultRandSource.wrap(plain).getStrength(),
                "wrap() of a random with no parameters must yield strength 0");
    }
}
