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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

/**
 * MT-66, FIPS half: the module's OWN RSA size floors, pinned per module.
 *
 * <p>The base twin is {@code RSAKeySizePinTest}. Neither substitutes for the
 * other: that one drives mainline libcrypto through the base library, this one
 * drives the validated module through the FIPS library, and the two disagree by
 * design.
 *
 * <p><b>Not a single golden list.</b> 3.1.2 and 3.5.8 were measured identical
 * for RSA sizes, but the point of MT-66 was that they need not be, so the
 * assertions are written per capability and self-arm on what the loaded module
 * actually does rather than on a version string.
 *
 * <h2>The module enforces FOUR floors, and they differ</h2>
 *
 * <pre>
 *   keygen  2048     sign  2048     verify  1024     import  none
 * </pre>
 *
 * <p>The verify floor of 1024 is SP 800-131A legacy verification, and it is the
 * row most easily got wrong: measuring verify with a signature the module
 * itself produced cannot reach it, because the module refuses to SIGN those
 * sizes. The MT-66 probe made exactly that mistake and reported "not attempted",
 * which reads as a refusal - the correct answer is ACCEPT from 1024 up.
 *
 * <p>JSLFIPS keeps a 2048 generation floor at the JCE boundary
 * ({@code ProvFIPSRSA}). That is a fast-path for the module's own refusal - a
 * typed {@code InvalidParameterException} instead of an {@code OpenSSLException}
 * from inside the module - NOT a jostle policy on top of it, and the two must
 * agree. {@link #theJceFloorAgreesWithTheModule} is what holds them together.
 */
public class FIPSRSAKeySizePinTest
{
    private static Provider fips;

    private static Provider jsl;

    @BeforeAll
    public static void setUp()
    {
        fips = FIPSTestUtil.assumeFipsProvider();
        // The verify-at-1024 row needs a 1024-bit key, which the module cannot
        // generate; JSL must therefore be registered here to make one.
        jsl = new org.openssl.jostle.jcajce.provider.JostleProvider();
        java.security.Security.addProvider(jsl);
    }

    /** Below the module's keygen floor: measured REFUSE on 3.1.2 and 3.5.8. */
    private static final int[] BELOW_KEYGEN_FLOOR = {512, 1024, 1536, 2047};

    /** At and above it: measured ACCEPT on both. */
    private static final int[] AT_OR_ABOVE_KEYGEN_FLOOR = {2048, 3072};

    /** Moduli the module IMPORTS regardless of size - it has no import floor. */
    private static final int[] IMPORTS = {64, 256, 511, 512, 1024, 2048};

    /**
     * The module imports anything. Measured: a 64-bit modulus is accepted by
     * both 3.1.2 and 3.5.8 through EVP_PKEY_fromdata. So a refusal here is a
     * jostle-side import floor having reappeared - the thing MT-66 removed.
     */
    @Test
    public void theModuleImportsAnySizeAndJostleDoesNotAddAFloor() throws Exception
    {
        for (int bits : IMPORTS)
        {
            BigInteger n = BigInteger.ONE.shiftLeft(bits - 1).or(BigInteger.ONE);
            KeyFactory kf = KeyFactory.getInstance("RSA", fips);
            Assertions.assertNotNull(
                    kf.generatePublic(new RSAPublicKeySpec(n, BigInteger.valueOf(65537))),
                    "the FIPS module imports a " + bits + "-bit modulus (measured); "
                            + "a refusal means a jostle import floor came back (MT-66)");
        }
    }

    /**
     * Drift signal: the module's generation floor moving. Refusal below 2048
     * and acceptance at 2048 are asserted as a PAIR, so a module that started
     * refusing everything cannot pass the first half alone.
     */
    @Test
    public void theModuleKeygenFloorIsWhereItWasMeasured() throws Exception
    {
        for (int bits : BELOW_KEYGEN_FLOOR)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", fips);
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
                    "FIPS RSA keygen at " + bits + " must be refused (measured on "
                            + "3.1.2 and 3.5.8); acceptance means the module's floor moved");
        }
        for (int bits : AT_OR_ABOVE_KEYGEN_FLOOR)
        {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", fips);
            g.initialize(bits);
            Assertions.assertNotNull(g.generateKeyPair(),
                    "FIPS RSA keygen at " + bits + " must work (measured); a refusal "
                            + "means the module's floor moved upward");
        }
    }

    /**
     * The JCE fast-path floor must AGREE with the module, not exceed it. If
     * ProvFIPSRSA's 2048 ever drifts above the module's own floor it would be a
     * jostle policy again, which is precisely what MT-66 removed - so the
     * agreement is asserted rather than assumed.
     */
    @Test
    public void theJceFloorAgreesWithTheModule() throws Exception
    {
        // 2048 is the module's floor AND ProvFIPSRSA's. The JCE floor refuses
        // early with a typed exception; the module refuses later. Both refuse
        // 2047 and both accept 2048 - that is the agreement.
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA", fips);
        java.security.InvalidParameterException e = Assertions.assertThrows(
                java.security.InvalidParameterException.class,
                () -> g.initialize(2047),
                "JSLFIPS must refuse 2047 early and typed");
        // The wording changed deliberately in MT-66: validateKeySize now
        // separates the sanity bound from the provider floor, so this is no
        // longer an "out of range" message. Pinned because it is
        // caller-visible and nothing else would catch it drifting back.
        Assertions.assertTrue(
                e.getMessage() != null
                        && e.getMessage().contains("below this provider's floor of 2048"),
                "the FIPS floor refusal must name the floor; got: " + e.getMessage());

        KeyPairGenerator ok = KeyPairGenerator.getInstance("RSA", fips);
        ok.initialize(2048);
        Assertions.assertNotNull(ok.generateKeyPair(),
                "JSLFIPS must accept 2048, the module's own floor");
    }

    /**
     * The verify floor is 1024, NOT 2048 - the row a self-signed probe cannot
     * see. A 1024-bit key cannot be generated by the module, so the key is
     * imported; verification of a signature made elsewhere is what the module
     * permits under SP 800-131A legacy verification.
     */
    @Test
    public void verifyIsPermittedFromTenTwentyFourEvenThoughSigningIsNot() throws Exception
    {
        // Generated by JSL, because the FIPS module cannot generate 1024 - the
        // same pattern FIPSTestUtil.dsaKeyPair uses for a module that refuses
        // DSA generation, and what a real caller on such a module must do.
        KeyPairGenerator jslGen = KeyPairGenerator.getInstance("RSA", jsl);
        jslGen.initialize(1024);
        java.security.KeyPair kp = jslGen.generateKeyPair();

        byte[] msg = new byte[32];
        new java.security.SecureRandom().nextBytes(msg);

        Signature signer = Signature.getInstance("SHA256withRSA", jsl);
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        // getEncoded() -> decode through the target provider's KeyFactory is
        // the ONLY sanctioned crossing (MT-14): a key object belongs to the
        // provider instance that made it.
        java.security.PublicKey fipsPub =
                FIPSTestUtil.crossPublic(kp.getPublic(), "RSA", "JSLFIPS");
        Signature v = Signature.getInstance("SHA256withRSA", fips);
        v.initVerify(fipsPub);
        v.update(msg);
        Assertions.assertTrue(v.verify(sig),
                "the FIPS module verifies at 1024 (SP 800-131A legacy verification, "
                        + "measured on 3.1.2 and 3.5.8) even though it will not sign there");
    }

    /** Vacuity guard: the tables must not be empty and RSA must be served. */
    @Test
    public void theModuleActuallyServesRsa() throws Exception
    {
        Assertions.assertNotNull(KeyPairGenerator.getInstance("RSA", fips));
        Assertions.assertNotNull(KeyFactory.getInstance("RSA", fips));
        Assertions.assertTrue(IMPORTS.length > 0 && BELOW_KEYGEN_FLOOR.length > 0
                && AT_OR_ABOVE_KEYGEN_FLOOR.length > 0, "tables must not be empty");
    }
}
