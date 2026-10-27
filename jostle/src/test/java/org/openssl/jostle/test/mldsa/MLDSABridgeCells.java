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

package org.openssl.jostle.test.mldsa;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSASignatureSpi;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * ML-DSA bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body pins
 * both interface libraries on whichever bridge the leg loads. The handle cells need no ML-DSA key and run on every
 * module; the key cells need a module that serves the family.
 */
public final class MLDSABridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};
    private static final byte[] NO_CONTEXT = new byte[0];
    private static final int KT_44 = OSSLKeyType.ML_DSA_44.getKsType();
    private static final int MU_INTERNAL = MLDSASignatureSpi.MuHandling.INTERNAL.ordinal();
    private static final int MU_EXTERNAL = MLDSASignatureSpi.MuHandling.EXTERNAL_MU.ordinal();
    private static final int MU_CALCULATE = MLDSASignatureSpi.MuHandling.CALCULATE_MU.ordinal();
    private static final int MU_BYTES = 64;

    private MLDSABridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * A key spec, a digest context, an RSA signer context and an SLH-DSA signer context as the ML-DSA context are
     * refused with a typed code at every session entry; an ML-DSA context as the key is refused at every key entry;
     * a dispose of the wrong kind frees nothing.
     */
    public static void wrongKindHandlesAreRefused(MLDSAServiceNI mldsa, SpecNI spec, RSAServiceNI rsa,
                                                  MDServiceNI md, SLHDSAServiceNI slhdsa)
    {
        int ctxWrong = code(ErrorCode.JO_MLDSA_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long rsaSigRef = rsa.allocateSigner();
        long mdRef = md.allocateDigest("SHA256", 0);
        long slhRef = slhdsa.allocateSigner();
        long ref = mldsa.allocateSigner();
        try
        {
            for (long bad : new long[]{keyRef, rsaSigRef, mdRef, slhRef})
            {
                Assertions.assertEquals(ctxWrong, mldsa.ni_initSign(bad, keyRef, NO_CONTEXT, 0, MU_INTERNAL, RND));
                Assertions.assertEquals(ctxWrong, mldsa.ni_initVerify(bad, keyRef, NO_CONTEXT, 0, MU_INTERNAL));
                Assertions.assertEquals(ctxWrong, mldsa.ni_update(bad, new byte[8], 0, 8));
                Assertions.assertEquals(ctxWrong, mldsa.ni_sign(bad, null, 0, RND));
                Assertions.assertEquals(ctxWrong, mldsa.ni_sign(bad, new byte[64], 0, RND));
                Assertions.assertEquals(ctxWrong, mldsa.ni_verify(bad, new byte[64], 64));
            }

            Assertions.assertEquals(specWrong, mldsa.ni_getPublicKey(ref, null));
            Assertions.assertEquals(specWrong, mldsa.ni_getPublicKey(ref, new byte[16]));
            Assertions.assertEquals(specWrong, mldsa.ni_getPrivateKey(ref, null));
            Assertions.assertEquals(specWrong, mldsa.ni_getPrivateKey(ref, new byte[16]));
            Assertions.assertEquals(specWrong, mldsa.ni_getSeed(ref, null));
            Assertions.assertEquals(specWrong, mldsa.ni_getSeed(ref, new byte[32]));
            Assertions.assertEquals(specWrong, mldsa.ni_decode_publicKey(ref, KT_44, new byte[1312], 0, 1312));
            Assertions.assertEquals(specWrong, mldsa.ni_decode_privateKey(ref, KT_44, new byte[32], 0, 32));
            Assertions.assertEquals(specWrong, mldsa.ni_initSign(ref, ref, NO_CONTEXT, 0, MU_INTERNAL, RND));
            Assertions.assertEquals(specWrong, mldsa.ni_initVerify(ref, ref, NO_CONTEXT, 0, MU_INTERNAL));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mldsa.update(mdRef, new byte[8], 0, 8));
            Assertions.assertEquals("handle is not an ML-DSA signer context", e.getMessage());
            e = Assertions.assertThrows(IllegalArgumentException.class, () -> mldsa.getPublicKey(ref, null));
            Assertions.assertEquals("handle is not a key spec", e.getMessage());

            // A dispose of the wrong kind frees nothing: each handle still answers as its own kind afterwards.
            mldsa.disposeSigner(keyRef);
            mldsa.disposeSigner(rsaSigRef);
            mldsa.disposeSigner(mdRef);
            mldsa.disposeSigner(slhRef);
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
            Assertions.assertEquals(code(ErrorCode.JO_SLHDSA_CTX_WRONG_KIND), slhdsa.ni_update(ref, new byte[8], 0, 8));
            Assertions.assertEquals(code(ErrorCode.JO_INCORRECT_KEY_TYPE),
                    mldsa.ni_initVerify(ref, keyRef, NO_CONTEXT, 0, MU_INTERNAL));
        }
        finally
        {
            mldsa.disposeSigner(ref);
            slhdsa.disposeSigner(slhRef);
            md.dispose(mdRef);
            rsa.disposeSigner(rsaSigRef);
            spec.dispose(keyRef);
        }
    }

    /** Each entry checks the context, then the key, then the RandSource, then the arrays. */
    public static void theContextThenTheKeyThenTheRandSourceAreChecked(MLDSAServiceNI mldsa, SpecNI spec)
    {
        int ctxWrong = code(ErrorCode.JO_MLDSA_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        int noRand = code(ErrorCode.JO_RAND_NO_RAND_UP_CALL);
        long keyRef = spec.allocate();
        long ref = mldsa.allocateSigner();
        try
        {
            Assertions.assertEquals(ctxWrong, mldsa.ni_initSign(keyRef, ref, null, 5, MU_INTERNAL, null));
            Assertions.assertEquals(specWrong, mldsa.ni_initSign(ref, ref, null, 5, MU_INTERNAL, null));
            Assertions.assertEquals(code(ErrorCode.JO_KEY_SPEC_IS_NULL),
                    mldsa.ni_initSign(ref, 0, null, 5, MU_INTERNAL, null));
            Assertions.assertEquals(noRand, mldsa.ni_initSign(ref, keyRef, null, 5, MU_INTERNAL, null));
            Assertions.assertEquals(code(ErrorCode.JO_CONTEXT_BYTES_NULL),
                    mldsa.ni_initSign(ref, keyRef, null, 5, MU_INTERNAL, RND));
            Assertions.assertEquals(ctxWrong, mldsa.ni_initVerify(keyRef, ref, null, 5, MU_INTERNAL));
            Assertions.assertEquals(specWrong, mldsa.ni_initVerify(ref, ref, null, 5, MU_INTERNAL));
            Assertions.assertEquals(code(ErrorCode.JO_CONTEXT_BYTES_NULL),
                    mldsa.ni_initVerify(ref, keyRef, null, 5, MU_INTERNAL));
            Assertions.assertEquals(ctxWrong, mldsa.ni_sign(keyRef, null, 0, null));
            Assertions.assertEquals(noRand, mldsa.ni_sign(ref, null, 0, null));
            Assertions.assertEquals(ctxWrong, mldsa.ni_update(keyRef, null, 0, 0));
            Assertions.assertEquals(code(ErrorCode.JO_INPUT_IS_NULL), mldsa.ni_update(ref, null, 0, 0));
            Assertions.assertEquals(ctxWrong, mldsa.ni_verify(keyRef, null, 0));
            Assertions.assertEquals(code(ErrorCode.JO_SIG_IS_NULL), mldsa.ni_verify(ref, null, 0));
        }
        finally
        {
            mldsa.disposeSigner(ref);
            spec.dispose(keyRef);
        }
    }

    /**
     * A key holding only its public half opens no signing session (INTERNAL and EXTERNAL refuse before anything is
     * allocated) and opens a mu session (CALCULATE_MU needs the public half only).
     */
    public static void aPublicOnlyKeyOpensOnlyAMuSession(MLDSAServiceNI mldsa, SpecNI spec)
    {
        long pairRef = mldsa.generateKeyPair(KT_44, RND);
        long pubRef = spec.allocate();
        long ref = mldsa.allocateSigner();
        try
        {
            byte[] pub = new byte[mldsa.getPublicKey(pairRef, null)];
            mldsa.getPublicKey(pairRef, pub);
            Assertions.assertEquals(0, mldsa.ni_decode_publicKey(pubRef, KT_44, pub, 0, pub.length));

            int noPrivate = code(ErrorCode.JO_KEY_HAS_NO_PRIVATE_HALF);
            Assertions.assertEquals(noPrivate, mldsa.ni_initSign(ref, pubRef, NO_CONTEXT, 0, MU_INTERNAL, RND));
            Assertions.assertEquals(code(ErrorCode.JO_NOT_INITIALIZED), mldsa.ni_sign(ref, new byte[4627], 0, RND));
            Assertions.assertEquals(noPrivate, mldsa.ni_initSign(ref, pubRef, NO_CONTEXT, 0, MU_EXTERNAL, RND));
            Assertions.assertEquals(0, mldsa.ni_initSign(ref, pubRef, NO_CONTEXT, 0, MU_CALCULATE, RND));
            Assertions.assertEquals(MU_BYTES, mldsa.ni_sign(ref, new byte[MU_BYTES], 0, RND));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> mldsa.initSign(ref, pubRef, NO_CONTEXT, 0, MU_INTERNAL, RND));
            Assertions.assertEquals("key has no private half", e.getMessage());

            // The full key still signs: the refusal reads the key, not the mode.
            Assertions.assertEquals(0, mldsa.ni_initSign(ref, pairRef, NO_CONTEXT, 0, MU_INTERNAL, RND));
            Assertions.assertEquals(0, mldsa.ni_initSign(ref, pairRef, NO_CONTEXT, 0, MU_EXTERNAL, RND));
        }
        finally
        {
            mldsa.disposeSigner(ref);
            spec.dispose(pubRef);
            spec.dispose(pairRef);
        }
    }

    /**
     * CALCULATE_MU on the verify side derives mu from the public key and the message and answers whether it equals
     * the 64 bytes passed as the signature: equal verifies, a flipped byte or any other length does not.
     */
    public static void aMuVerifiesThroughTheCalculateMode(MLDSAServiceNI mldsa, SpecNI spec)
    {
        long pairRef = mldsa.generateKeyPair(KT_44, RND);
        long ref = mldsa.allocateSigner();
        try
        {
            byte[] msg = new byte[1 + RANDOM.nextInt(256)];
            RANDOM.nextBytes(msg);
            byte[] ctx = new byte[1 + RANDOM.nextInt(255)];
            RANDOM.nextBytes(ctx);
            Assertions.assertEquals(0, mldsa.ni_initSign(ref, pairRef, ctx, ctx.length, MU_CALCULATE, RND));
            Assertions.assertEquals(0, mldsa.ni_update(ref, msg, 0, msg.length));
            byte[] mu = new byte[MU_BYTES];
            Assertions.assertEquals(MU_BYTES, mldsa.ni_sign(ref, mu, 0, RND));

            int ok = code(ErrorCode.JO_SUCCESS);
            int fail = code(ErrorCode.JO_FAIL);
            Assertions.assertEquals(ok, verifyMu(mldsa, ref, pairRef, ctx, msg, mu, MU_BYTES));
            byte[] flipped = mu.clone();
            flipped[MU_BYTES - 1] ^= 1;
            Assertions.assertEquals(fail, verifyMu(mldsa, ref, pairRef, ctx, msg, flipped, MU_BYTES));
            Assertions.assertEquals(fail, verifyMu(mldsa, ref, pairRef, ctx, msg, mu, MU_BYTES - 1));
            byte[] longer = new byte[MU_BYTES + 1];
            System.arraycopy(mu, 0, longer, 0, MU_BYTES);
            Assertions.assertEquals(fail, verifyMu(mldsa, ref, pairRef, ctx, msg, longer, MU_BYTES + 1));
            byte[] otherCtx = ctx.clone();
            otherCtx[0] ^= 1;
            Assertions.assertEquals(fail, verifyMu(mldsa, ref, pairRef, otherCtx, msg, mu, MU_BYTES));
        }
        finally
        {
            mldsa.disposeSigner(ref);
            spec.dispose(pairRef);
        }
    }

    private static int verifyMu(MLDSAServiceNI mldsa, long ref, long keyRef, byte[] ctx, byte[] msg, byte[] mu,
                                int muLen)
    {
        Assertions.assertEquals(0, mldsa.ni_initVerify(ref, keyRef, ctx, ctx.length, MU_CALCULATE));
        Assertions.assertEquals(0, mldsa.ni_update(ref, msg, 0, msg.length));
        return mldsa.ni_verify(ref, mu, muLen);
    }
}
