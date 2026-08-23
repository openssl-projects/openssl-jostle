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
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.FIPSNISelector;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.provider.fips.OpenSSLFIPSNI;
import org.openssl.jostle.jcajce.spec.MLDSAParameterSpec;
import org.openssl.jostle.test.TestUtil;

import java.security.DrbgParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * The PQ Random accommodation for JSLFIPS.
 *
 * <p>Lives in {@code src/test/java25} because it uses {@link DrbgParameters}
 * to construct a SecureRandom that REPORTS a specific strength - the baseline
 * test source set compiles at release 8, where that API does not exist.
 *
 * <p>Gated on {@code TEST_FIPS_LIB}; skipped when unset.
 */
public class FIPSPQCRandomTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String JSL = JostleProvider.PROVIDER_NAME;

    private static final SecureRandom RANDOM = new SecureRandom();

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        if (Security.getProvider(JSL) == null)
        {
            Security.addProvider(new JostleProvider());
        }
    }

    /** Does JSLFIPS carry the family, and does that agree with the module? */
    private static boolean served(String kpgAlg, String fetchName)
    {
        boolean registered = Security.getProvider(FIPS)
                .getService("KeyPairGenerator", kpgAlg) != null;
        int fetch = FIPSNISelector.OpenSSLFIPSNI.canFetch(OpenSSLFIPSNI.OP_KEYMGMT, fetchName);
        Assertions.assertEquals(registered, fetch != 0,
                kpgAlg + ": registration disagrees with the module's keymgmt fetch");
        return registered;
    }

    /**
     * The Random accommodation, asserted on BOTH providers in one test.
     * <p>
     * The PQ SPIs normally reject a caller-supplied SecureRandom whose reported
     * strength is below the parameter set's requirement. Under the FIPS module
     * that check is wrong: the module supplies its own entropy and never
     * consults the caller's value (the FIPS lib ctx omits the
     * {@code java_rand_bridge}), so rejecting turns a caller away over
     * something nothing reads - and the C-side
     * {@code JO_RAND_INSUFFICIENT_STRENGTH} backstop cannot fire there either.
     * <p>
     * The generated key must then actually work. Without the sign/verify step
     * this would degrade into "no exception was thrown", which a broken keygen
     * would also satisfy.
     */
    @Test
    public void weakSecureRandomRejectedByJslButAcceptedByFips() throws Exception
    {
        SecureRandom weak = weak128BitDrbg();
        if (weak == null)
        {
            return; // no DRBG with an explicit strength on this JVM
        }

        // JSL: the caller's SecureRandom IS used, so the strength gate applies.
        KeyPairGenerator jsl = KeyPairGenerator.getInstance("ML-DSA-87", JSL);
        Assertions.assertThrows(InvalidAlgorithmParameterException.class,
                () -> jsl.initialize(MLDSAParameterSpec.ml_dsa_87, weak),
                "JSL must reject a 128-bit DRBG for ML-DSA-87");

        if (!served("ML-DSA-87", "ML-DSA-87"))
        {
            return;
        }

        // JSLFIPS: accepted, because the module supplies entropy regardless.
        KeyPairGenerator fips = KeyPairGenerator.getInstance("ML-DSA-87", FIPS);
        fips.initialize(MLDSAParameterSpec.ml_dsa_87, weak);
        KeyPair kp = fips.generateKeyPair();

        byte[] msg = new byte[32];
        RANDOM.nextBytes(msg);
        Signature s = Signature.getInstance("ML-DSA-87", FIPS);
        s.initSign(kp.getPrivate());
        s.update(msg);
        byte[] sig = s.sign();

        Signature v = Signature.getInstance("ML-DSA-87", FIPS);
        v.initVerify(kp.getPublic());
        v.update(msg);
        Assertions.assertTrue(v.verify(sig),
                "the key generated under a weak caller SecureRandom must still work - "
                        + "accepting the call is only correct if the module really did the work");
    }

    /**
     * A DRBG that reports 128-bit strength, or null when this JVM cannot make
     * one. Returns null rather than skipping the whole test so the JSL half
     * still runs wherever it can.
     */
    private static SecureRandom weak128BitDrbg()
    {
        try
        {
            return SecureRandom.getInstance("DRBG",
                    DrbgParameters.instantiation(128, DrbgParameters.Capability.RESEED_ONLY, null));
        }
        catch (Exception e)
        {
            return null;
        }
    }
}
