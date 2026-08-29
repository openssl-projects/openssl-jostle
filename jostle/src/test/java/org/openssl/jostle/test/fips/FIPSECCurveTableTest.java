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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.JostleProvider;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.test.TestUtil;
import org.openssl.jostle.util.Arrays;

import java.security.AlgorithmParameters;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * The EC curve table is read from libcrypto, not from the FIPS module, and that
 * difference is a decision rather than an accident.
 *
 * <p><b>The decision.</b> {@code EC_GROUP_new_by_curve_name_ex} reads a static
 * table in libcrypto; providers are not consulted. Measured under a FIPS lib
 * ctx: the group for secp256k1 and brainpoolP256r1 is PRESENT while
 * {@code EVP_PKEY_paramgen} refuses both. So describing a curve and operating
 * on one give different answers, and this provider deliberately keeps them
 * different — encoding domain parameters describes a curve, it is not an
 * operation on it.
 *
 * <p>Pinned in BOTH directions so a future change that gates the lookup fails
 * here and has to name the decision it is reversing.
 */
public class FIPSECCurveTableTest
{
    private static Provider fips;
    private static Provider jsl;

    /**
     * A curve libcrypto's table holds and the module will not generate on.
     * secp256k1 is the Koblitz prime curve; it is not in SP 800-186's approved
     * set, so no module configuration turns it on.
     */
    private static final String UNAPPROVED_CURVE = "secp256k1";

    /** An approved curve, as the control. */
    private static final String APPROVED_CURVE = "prime256v1";

    @BeforeAll
    public static void beforeAll()
    {
        Assumptions.assumeFalse(TestUtil.skipFipsTests(),
                "TEST_FIPS_LIB not set (full path to the FIPS module library)");
        TestUtil.addFipsProvider();
        if (Security.getProvider(JostleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new JostleProvider());
        }
        fips = Security.getProvider(JostleFIPSProvider.PROVIDER_NAME);
        jsl = Security.getProvider(JostleProvider.PROVIDER_NAME);
        Assertions.assertNotNull(fips, "the FIPS provider must be registered");
    }

    /**
     * The whole point: JSLFIPS DESCRIBES a curve it will not OPERATE on.
     *
     * <p>Both halves asserted together, because either alone is satisfiable by
     * the wrong implementation — a gated lookup passes the refusal half, and an
     * ungated generator passes the description half.
     */
    @Test
    public void anUnapprovedCurveIsDescribedButNotGeneratedOn() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", fips);
        ap.init(new ECGenParameterSpec(UNAPPROVED_CURVE));
        ECParameterSpec described = ap.getParameterSpec(ECParameterSpec.class);
        Assertions.assertNotNull(described,
                UNAPPROVED_CURVE + " must still be describable through JSLFIPS");
        Assertions.assertEquals(256, described.getCurve().getField().getFieldSize());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", fips);
        Assertions.assertThrows(Exception.class,
                () -> generator.initialize(new ECGenParameterSpec(UNAPPROVED_CURVE)),
                UNAPPROVED_CURVE + " must be refused for key generation by the module");
    }

    /**
     * The control that stops the test above from passing on a provider that
     * refuses everything: an approved curve must both describe AND generate.
     */
    @Test
    public void anApprovedCurveIsBothDescribedAndGeneratedOn() throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", fips);
        ap.init(new ECGenParameterSpec(APPROVED_CURVE));
        Assertions.assertNotNull(ap.getParameterSpec(ECParameterSpec.class));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", fips);
        generator.initialize(new ECGenParameterSpec(APPROVED_CURVE));
        Assertions.assertNotNull(generator.generateKeyPair());
    }

    /**
     * The two providers read the same libcrypto table, so their descriptions of
     * a curve must be identical — including for a curve only one of them will
     * operate on. A FIPS build that had silently acquired its own curve source
     * would diverge here.
     */
    @Test
    public void bothProvidersDescribeACurveIdentically() throws Exception
    {
        for (String curve : new String[]{APPROVED_CURVE, UNAPPROVED_CURVE, "sect233r1"})
        {
            AlgorithmParameters fipsParams = AlgorithmParameters.getInstance("EC", fips);
            AlgorithmParameters jslParams = AlgorithmParameters.getInstance("EC", jsl);
            try
            {
                fipsParams.init(new ECGenParameterSpec(curve));
                jslParams.init(new ECGenParameterSpec(curve));
            }
            catch (Exception notInThisBuild)
            {
                continue;
            }
            Assertions.assertTrue(Arrays.areEqual(
                            jslParams.getEncoded(), fipsParams.getEncoded()),
                    curve + " must encode identically through both providers");

            ECParameterSpec a = jslParams.getParameterSpec(ECParameterSpec.class);
            ECParameterSpec b = fipsParams.getParameterSpec(ECParameterSpec.class);
            Assertions.assertEquals(a.getCurve(), b.getCurve(), curve);
            Assertions.assertEquals(a.getGenerator(), b.getGenerator(), curve);
            Assertions.assertEquals(a.getOrder(), b.getOrder(), curve);
            Assertions.assertEquals(a.getCofactor(), b.getCofactor(), curve);
        }
    }

    /**
     * JSLFIPS's EC AlgorithmParameters is served by JSLFIPS, and answers the
     * fixed X9.62 encoding rather than whatever else is installed.
     */
    @Test
    public void theFipsEcAlgorithmParametersServiceIsServedByTheFipsProvider()
        throws Exception
    {
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC", fips);
        Assertions.assertEquals(JostleFIPSProvider.PROVIDER_NAME,
                ap.getProvider().getName());
        ap.init(new ECGenParameterSpec(APPROVED_CURVE));
        Assertions.assertArrayEquals(
                new byte[]{0x06, 0x08, 0x2A, (byte) 0x86, 0x48, (byte) 0xCE,
                        0x3D, 0x03, 0x01, 0x07},
                ap.getEncoded());
    }
}
