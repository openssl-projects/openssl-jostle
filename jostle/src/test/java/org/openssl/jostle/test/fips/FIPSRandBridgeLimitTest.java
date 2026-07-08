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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.ec.ECServiceNI;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * FIPS counterpart to {@code BridgeRandLimitTest}. The base test proves the
 * Java entropy up-call handler correctly surfaces a broken {@link RandSource}
 * (short/long/throwing/failing) as a typed error — because in the non-FIPS
 * build every keygen draws its entropy through the Jostle Java RAND bridge
 * ({@code interface/fips/util/rand/jostle_lib_ctx.c}).
 *
 * <p>Under FIPS that up-call is <b>deliberately absent</b>: the FIPS lib ctx
 * installs no {@code java_rand_bridge}, so entropy stays inside the validated
 * module boundary, served by the module's own approved DRBGs (see
 * {@code interface/fips/util/rand/jostle_fips_ctx.c}: "No java_rand_bridge in a FIPS
 * context: entropy stays inside the FIPS boundary"). That is a
 * FIPS-certification requirement, not an implementation detail — entropy for
 * an approved keygen must not come from an arbitrary Java {@code SecureRandom}.
 *
 * <p>So there is no up-call error path to mirror; the meaningful test is the
 * <b>inverse hard-guard</b>. Each keygen still accepts a {@code RandSource}
 * parameter (and the bridge still null-checks it — see the null tests), but the
 * FIPS entropy path must never actually consult it. These tests pass a
 * deliberately <em>poisoned</em> source that (a) counts every invocation and
 * (b) returns a failing code that would abort keygen if it were ever consulted.
 * A successful keygen with a zero invocation count is the only outcome
 * consistent with entropy staying in the FIPS boundary. If a future change
 * accidentally wires the Java bridge into the FIPS path, keygen fails loudly
 * AND the counter goes non-zero — this guard is designed to detonate then,
 * rather than let a compliance regression sit latent until it surfaces in
 * production / a certification audit.
 *
 * <p>Two independent keygen entry points are covered (EC and RSA), because each
 * is a separate {@code rand_set_java_srand_call} site in the C bridge — a leak
 * could be introduced at one without the other.
 *
 * <p>Runs under the {@code integrationTest*} tasks; gated on
 * {@code TEST_FIPS_LIB} (whole class skips when unset).
 */
public class FIPSRandBridgeLimitTest
{
    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
    }

    private final ECServiceNI ecNI = FIPSNISelector.ECServiceNI;
    private final RSAServiceNI rsaNI = FIPSNISelector.RSAServiceNI;
    private final SpecNI specNI = FIPSNISelector.SpecNI;

    // ---------------------------------------------------------------------
    // Entropy stays in the FIPS boundary: the Java RandSource is never
    // consulted by an approved keygen.
    // ---------------------------------------------------------------------

    @Test
    public void ecKeygen_doesNotConsultJavaRandSource()
    {
        PoisonRandSource poison = new PoisonRandSource();
        // If the FIPS keygen consulted the source, the -999 return would abort
        // it (thrown OpenSSLException) — so a successful ref is proof of
        // non-consultation, and the counter is the belt-and-suspenders check.
        long ref = ecNI.generateKeyPair("P-256", poison);
        try
        {
            Assertions.assertTrue(ref > 0, "FIPS EC keygen did not produce a key");
            Assertions.assertEquals(0, poison.calls,
                    "FIPS EC keygen consulted the Java RandSource — entropy escaped the module boundary");
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    @Test
    public void rsaKeygen_doesNotConsultJavaRandSource()
    {
        PoisonRandSource poison = new PoisonRandSource();
        long ref = rsaNI.generateKeyPair(2048, new byte[]{0x01, 0x00, 0x01}, poison);
        try
        {
            Assertions.assertTrue(ref > 0, "FIPS RSA keygen did not produce a key");
            Assertions.assertEquals(0, poison.calls,
                    "FIPS RSA keygen consulted the Java RandSource — entropy escaped the module boundary");
        }
        finally
        {
            specNI.dispose(ref);
        }
    }

    // ---------------------------------------------------------------------
    // The bridge still null-checks the RandSource parameter (input validation
    // survived the FIPS re-include), even though the source is never used.
    // ---------------------------------------------------------------------

    @Test
    public void ecKeygen_rejectsNullRandSource()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> ecNI.generateKeyPair("P-256", null));
        Assertions.assertEquals("supplied random source was null", e.getMessage());
    }

    @Test
    public void rsaKeygen_rejectsNullRandSource()
    {
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> rsaNI.generateKeyPair(2048, new byte[]{0x01, 0x00, 0x01}, null));
        Assertions.assertEquals("supplied random source was null", e.getMessage());
    }

    /**
     * A RandSource that must never be consulted by the FIPS entropy path: it
     * counts every call and returns a failing code (-999) that would abort any
     * keygen unlucky enough to actually invoke it.
     */
    public static final class PoisonRandSource implements RandSource
    {
        volatile int calls = 0;

        @Override
        public int getRandomBytes(byte[] out, int len, int strength, boolean predictionResistant)
        {
            calls++;
            return -999;
        }

        @Override
        public SecureRandom getRandom()
        {
            return null;
        }

        @Override
        public int getStrength()
        {
            return 256;
        }
    }
}
