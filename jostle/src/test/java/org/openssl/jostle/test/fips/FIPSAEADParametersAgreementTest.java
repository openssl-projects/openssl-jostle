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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.openssl.jostle.jcajce.provider.fips.JostleFIPSProvider;
import org.openssl.jostle.jcajce.spec.AEADParameterSpec;

import javax.crypto.spec.GCMParameterSpec;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * The JSLFIPS half of AEADParametersAgreementTest: the GCM and CCM AlgorithmParameters take the provider's own
 * AEADParameterSpec, encode it as a GCMParameterSpec and as BouncyCastle 1.87's AEADParameterSpec, and read it back.
 */
public class FIPSAEADParametersAgreementTest
{
    private static final String FIPS = JostleFIPSProvider.PROVIDER_NAME;
    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Object[][] MODES = {
        {"GCM", 12, new int[]{96, 104, 112, 120, 128}},
        {"CCM", 13, new int[]{32, 48, 64, 80, 96, 112, 128}}};

    @BeforeAll
    static void before()
    {
        FIPSTestUtil.assumeFipsProvider();
        if (Security.getProvider(BC) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Every allowed tag length: the encoding equals the GCM spec's and BouncyCastle's, and reads back. */
    @Test
    public void aeadSpecEncodesAsTheGcmSpecAndAsBouncyCastle() throws Exception
    {
        int checked = 0;
        for (Object[] m : MODES)
        {
            String mode = (String) m[0];
            for (int bits : (int[]) m[2])
            {
                byte[] nonce = new byte[(Integer) m[1]];
                RANDOM.nextBytes(nonce);
                String label = mode + " tag " + bits;

                AlgorithmParameters viaAead = AlgorithmParameters.getInstance(mode, FIPS);
                viaAead.init(new AEADParameterSpec(nonce, bits));
                AlgorithmParameters viaGcm = AlgorithmParameters.getInstance(mode, FIPS);
                viaGcm.init(new GCMParameterSpec(bits, nonce));
                AlgorithmParameters bc = AlgorithmParameters.getInstance(mode, BC);
                // AEADParameterSpec: BouncyCastle's is qualified, jostle's is imported
                bc.init(new org.bouncycastle.jcajce.spec.AEADParameterSpec(nonce, bits));

                Assertions.assertArrayEquals(viaGcm.getEncoded(), viaAead.getEncoded(), label);
                Assertions.assertArrayEquals(bc.getEncoded(), viaAead.getEncoded(), label + " against BouncyCastle");
                AEADParameterSpec back = viaAead.getParameterSpec(AEADParameterSpec.class);
                Assertions.assertArrayEquals(nonce, back.getNonce(), label);
                Assertions.assertEquals(bits, back.getMacSizeInBits(), label);
                checked++;
            }
        }
        Assertions.assertEquals(5 + 7, checked, "every mode and tag length must be driven");
    }

    /** A tag length the mode does not allow is refused with InvalidParameterSpecException. */
    @Test
    public void aTagLengthTheModeDoesNotAllowIsRefused() throws Exception
    {
        Object[][] cells = {{"GCM", 12, 64}, {"CCM", 13, 72}};
        for (Object[] c : cells)
        {
            AlgorithmParameters ours = AlgorithmParameters.getInstance((String) c[0], FIPS);
            assertThrows(InvalidParameterSpecException.class,
                    () -> ours.init(new AEADParameterSpec(new byte[(Integer) c[1]], (Integer) c[2])), c[0] + "");
        }
    }
}
