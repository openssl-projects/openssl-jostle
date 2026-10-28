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

package org.openssl.jostle.test.mlkem;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mlkem.MLKEMServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

/**
 * ML-KEM bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body pins
 * both interface libraries on whichever bridge the leg loads. None needs an ML-KEM key, so they run on every module.
 */
public final class MLKEMBridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final int KT_768 = OSSLKeyType.ML_KEM_768.getKsType();

    private MLKEMBridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * An ML-DSA signer context, an SLH-DSA signer context and a digest context as the key spec are refused with a
     * typed code at every getter and both decoders, and nothing is written into them: each still answers as its own
     * kind afterwards.
     */
    public static void wrongKindHandlesAreRefused(MLKEMServiceNI mlkem, MLDSAServiceNI mldsa, SLHDSAServiceNI slhdsa,
                                                  MDServiceNI md)
    {
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long mldsaRef = mldsa.allocateSigner();
        long slhdsaRef = slhdsa.allocateSigner();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            for (long bad : new long[]{mldsaRef, slhdsaRef, mdRef})
            {
                Assertions.assertEquals(specWrong, mlkem.ni_getPublicKey(bad, null));
                Assertions.assertEquals(specWrong, mlkem.ni_getPublicKey(bad, new byte[1184]));
                Assertions.assertEquals(specWrong, mlkem.ni_getPrivateKey(bad, null));
                Assertions.assertEquals(specWrong, mlkem.ni_getPrivateKey(bad, new byte[2400]));
                Assertions.assertEquals(specWrong, mlkem.ni_getSeed(bad, null));
                Assertions.assertEquals(specWrong, mlkem.ni_getSeed(bad, new byte[64]));
                Assertions.assertEquals(specWrong,
                        mlkem.ni_decode_publicKey(bad, KT_768, new byte[1184], 0, 1184, RND));
                Assertions.assertEquals(specWrong,
                        mlkem.ni_decode_privateKey(bad, KT_768, new byte[2400], 0, 2400, RND));
            }

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mlkem.getPublicKey(mldsaRef, null));
            Assertions.assertEquals("handle is not a key spec", e.getMessage());

            // Nothing was written into the foreign objects: each still answers as its own kind.
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
            Assertions.assertEquals(code(ErrorCode.JO_NOT_INITIALIZED), mldsa.ni_update(mldsaRef, new byte[8], 0, 8));
            Assertions.assertEquals(code(ErrorCode.JO_NOT_INITIALIZED),
                    slhdsa.ni_update(slhdsaRef, new byte[8], 0, 8));
        }
        finally
        {
            md.dispose(mdRef);
            slhdsa.disposeSigner(slhdsaRef);
            mldsa.disposeSigner(mldsaRef);
        }
    }

    /** Each decoder checks the key spec, then the RandSource, then the input; the getters check the key spec. */
    public static void theSpecThenTheRandSourceThenTheInputAreChecked(MLKEMServiceNI mlkem, SpecNI spec,
                                                                     MDServiceNI md)
    {
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        int specNull = code(ErrorCode.JO_KEY_SPEC_IS_NULL);
        int noRand = code(ErrorCode.JO_RAND_NO_RAND_UP_CALL);
        int inputNull = code(ErrorCode.JO_INPUT_IS_NULL);
        long keyRef = spec.allocate();
        long mdRef = md.allocateDigest("SHA256", 0);
        try
        {
            Assertions.assertEquals(specNull, mlkem.ni_getPublicKey(0, null));
            Assertions.assertEquals(specNull, mlkem.ni_getPrivateKey(0, null));
            Assertions.assertEquals(specNull, mlkem.ni_getSeed(0, null));

            Assertions.assertEquals(specNull, mlkem.ni_decode_publicKey(0, KT_768, null, -1, -1, null));
            Assertions.assertEquals(specWrong, mlkem.ni_decode_publicKey(mdRef, KT_768, null, -1, -1, null));
            Assertions.assertEquals(noRand, mlkem.ni_decode_publicKey(keyRef, KT_768, null, -1, -1, null));
            Assertions.assertEquals(inputNull, mlkem.ni_decode_publicKey(keyRef, KT_768, null, -1, -1, RND));

            Assertions.assertEquals(specNull, mlkem.ni_decode_privateKey(0, KT_768, null, -1, -1, null));
            Assertions.assertEquals(specWrong, mlkem.ni_decode_privateKey(mdRef, KT_768, null, -1, -1, null));
            Assertions.assertEquals(noRand, mlkem.ni_decode_privateKey(keyRef, KT_768, null, -1, -1, null));
            Assertions.assertEquals(inputNull, mlkem.ni_decode_privateKey(keyRef, KT_768, null, -1, -1, RND));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mlkem.decode_privateKey(keyRef, KT_768, new byte[2400], 0, 2400, null));
            Assertions.assertEquals("supplied random source was null", e.getMessage());
        }
        finally
        {
            md.dispose(mdRef);
            spec.dispose(keyRef);
        }
    }
}
