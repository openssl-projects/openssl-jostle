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

package org.openssl.jostle.test.rsa;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;

/**
 * MT-66: RSA key sizes are the MODULE's decision, and this pins that it stays
 * that way. Replaces {@code RSAKeyFloorTest}, whose two floors this work
 * removed.
 *
 * <h2>What changed and why</h2>
 *
 * <p>Ruling (Megan, 2026-09-05): jostle supports what OpenSSL supports, for
 * every module type - default, FIPS 3.1.2 and FIPS 3.5.8. There is no
 * jostle-side policy floor. Measured, two floors refused what the library
 * accepts: the 512-bit IMPORT floor (OpenSSL imports a 64-bit key on all three
 * configurations) and the 1024-bit JSL GENERATION floor (the default provider
 * generates from 512).
 *
 * <h2>The bypass MT-46 named is dissolved, not reopened</h2>
 *
 * <p>MT-46's concern was a GAP: generation refused 512 while import accepted a
 * twelve-bit modulus, so the generation policy could be bypassed by encoding a
 * key and reading it back. The gap existed because two jostle-side numbers
 * disagreed. With both removed, both doors defer to the module - and the module
 * was measured identical at both. There is no longer a policy to bypass.
 *
 * <h2>Two failure modes this test MUST have</h2>
 *
 * <ol>
 *   <li>A reintroduced jostle-side floor - a refusal where the table says the
 *       size is accepted.</li>
 *   <li>Module drift - the module's own floors moving under us.</li>
 * </ol>
 *
 * <p><b>Deliberately NOT a single golden list.</b> The two FIPS modules agree
 * today and need not tomorrow; that is the whole reason MT-66 measured per
 * module rather than once. The JSL rows below are what the base provider must
 * do; {@code FIPSRSAKeySizePinTest} holds the FIPS side and self-arms on the
 * loaded module.
 *
 * <h2>The measured table (MT-66), for reference</h2>
 *
 * <pre>
 *   bits   default: gen imp sign ver   FIPS 3.1.2 == 3.5.8: gen imp sign ver
 *     64            -   A    -    -                          -   A   -    -
 *    511            -   A    -    -                          -   A   -    -
 *    512            A   A    A    A                          x   A   x    x
 *   1023            A   A    A    A                          x   A   x    x
 *   1024            A   A    A    A                          x   A   x    A
 *   2047            A   A    A    A                          x   A   x    A
 *   2048            A   A    A    A                          A   A   A    A
 * </pre>
 *
 * <p>"-" means UNREACHABLE, not refused: OpenSSL will not GENERATE below 512,
 * so no key of that size exists to drive gen/sign/verify. The import column
 * there comes from constructed keys. Recording those cells as "-" rather than
 * leaving them blank is deliberate - the MT-66 instrument reported exactly
 * those cells in the language of a result ("no reference key", "not attempted")
 * and both readings were the opposite of the truth.
 *
 * <p>The FIPS module enforces FOUR different floors: keygen 2048, sign 2048,
 * verify 1024, import none. No single number expresses that, which is the
 * second reason a jostle-side floor could not be right.
 */
public class RSAKeySizePinTest
{
    private static Provider jsl;

    /** Sizes the DEFAULT provider generates. A refusal here is a reintroduced floor. */
    private static final int[] GENERATES = {512, 513, 768, 1023, 1024, 1536, 2048};

    /** Sizes below OpenSSL's own 512-bit keygen floor: it refuses these itself. */
    private static final int[] BELOW_OPENSSL_KEYGEN_FLOOR = {256, 384, 511};

    /** Moduli the library imports. 64 bits is measured-accepted on every module. */
    private static final int[] IMPORTS = {64, 128, 256, 384, 511, 512, 768, 1024, 2048};

    @BeforeAll
    public static void setUp()
    {
        jsl = new JostleProvider();
        Security.addProvider(jsl);
    }

    /**
     * Failure mode 1, generation: a jostle-side floor reappearing shows up as a
     * refusal at a size OpenSSL generates. 512/513/768/1023 are the sizes the
     * old 1024 floor refused, so they are the ones that catch its return.
     */
    @Test
    public void everySizeOpenSSLGeneratesIsAccepted() throws Exception
    {
        for (int bits : GENERATES)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", jsl);
            // initialize() is where a policy floor lives; generateKeyPair()
            // would also exercise the module. Both must pass.
            g.initialize(bits);
            Assertions.assertNotNull(g.generateKeyPair(),
                    "RSA " + bits + " must generate: OpenSSL accepts it and jostle "
                            + "has no policy floor (MT-66)");
        }
    }

    /**
     * Failure mode 2, generation: OpenSSL's OWN floor is 512, and if it moves
     * this fails - which is the drift signal. Note the refusal must come from
     * the library, not from us; we assert only that it IS refused.
     */
    @Test
    public void sizesBelowOpenSSLsOwnKeygenFloorAreRefused() throws Exception
    {
        for (int bits : BELOW_OPENSSL_KEYGEN_FLOOR)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", jsl);
            boolean refused = false;
            try
            {
                g.initialize(bits);
                g.generateKeyPair();
            }
            catch (Exception e)
            {
                refused = true;
            }
            Assertions.assertTrue(refused,
                    "RSA " + bits + " is below OpenSSL's own keygen floor and must be "
                            + "refused; if this passes the module's floor moved (MT-66)");
        }
    }

    /**
     * Failure mode 1, import: the 512 floor's return shows up here. A 64-bit
     * modulus is measured-accepted by OpenSSL on every module, so it is the
     * sharpest probe - it was also the shape MT-46 originally refused.
     */
    @Test
    public void everyModulusOpenSSLImportsIsAccepted() throws Exception
    {
        for (int bits : IMPORTS)
        {
            BigInteger n = BigInteger.ONE.shiftLeft(bits - 1).or(BigInteger.ONE);
            KeyFactory kf = KeyFactory.getInstance("RSA", jsl);
            Assertions.assertNotNull(
                    kf.generatePublic(new RSAPublicKeySpec(n, BigInteger.valueOf(65537))),
                    "RSA modulus of " + bits + " bits must import: OpenSSL accepts it "
                            + "and jostle has no import floor (MT-66)");
        }
    }

    /**
     * The sanity bound is NOT a policy floor and must survive. A non-positive
     * size is nonsense at every provider and would otherwise cross the bridge
     * as a bits value.
     */
    @Test
    public void nonPositiveAndAbsurdSizesAreStillRefused() throws Exception
    {
        int[] bad = {0, -1, Integer.MIN_VALUE, 16385, Integer.MAX_VALUE};
        for (int bits : bad)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", jsl);
            Assertions.assertThrows(java.security.InvalidParameterException.class,
                    () -> g.initialize(bits),
                    "RSA key size " + bits + " must be refused by the sanity bound, "
                            + "which MT-66 did NOT remove");
        }
    }

    /**
     * Vacuity guard. If the provider stopped serving RSA entirely, every
     * assertion above would still pass or skip in ways that read as health.
     */
    @Test
    public void theProviderActuallyServesRsa() throws Exception
    {
        Assertions.assertNotNull(KeyPairGenerator.getInstance("RSA", jsl));
        Assertions.assertNotNull(KeyFactory.getInstance("RSA", jsl));
        Assertions.assertTrue(GENERATES.length > 0 && IMPORTS.length > 0,
                "the tables must not be empty");
    }
}
