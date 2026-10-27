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

package org.openssl.jostle.test.slhdsa;

import org.junit.jupiter.api.Assertions;
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.mldsa.MLDSAServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSAServiceNI;
import org.openssl.jostle.jcajce.provider.slhdsa.SLHDSASignatureSpi;
import org.openssl.jostle.jcajce.spec.OSSLKeyType;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

import java.security.SecureRandom;

/**
 * SLH-DSA bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body pins
 * both interface libraries on whichever bridge the leg loads. The handle cells need no SLH-DSA key and run on every
 * module; the key cells need a module that serves the family.
 */
public final class SLHDSABridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] PUB_EXP_F4 = {0x01, 0x00, 0x01};
    private static final byte[] NO_CONTEXT = new byte[0];
    private static final int KT_128F = OSSLKeyType.SLH_DSA_SHA2_128f.getKsType();
    private static final int PURE = SLHDSASignatureSpi.MessageEncoding.PURE.ordinal();
    private static final int NO_ENCODING = SLHDSASignatureSpi.MessageEncoding.NONE.ordinal();
    private static final int HEDGED = SLHDSASignatureSpi.Deterministic.NON_DETERMINISTIC.ordinal();
    // n for the 128 sets: the private key is 4n bytes, the seed 3n.
    private static final int N_128 = 16;

    private SLHDSABridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * A key spec, a digest context, an RSA signer context and an ML-DSA signer context as the SLH-DSA context are
     * refused with a typed code at every session entry; an SLH-DSA context as the key is refused at every key entry;
     * a dispose of the wrong kind frees nothing.
     */
    public static void wrongKindHandlesAreRefused(SLHDSAServiceNI slhdsa, SpecNI spec, RSAServiceNI rsa,
                                                  MDServiceNI md, MLDSAServiceNI mldsa)
    {
        int ctxWrong = code(ErrorCode.JO_SLHDSA_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = rsa.generateKeyPair(2048, PUB_EXP_F4, RND);
        long rsaSigRef = rsa.allocateSigner();
        long mdRef = md.allocateDigest("SHA256", 0);
        long mldsaRef = mldsa.allocateSigner();
        long ref = slhdsa.allocateSigner();
        try
        {
            for (long bad : new long[]{keyRef, rsaSigRef, mdRef, mldsaRef})
            {
                Assertions.assertEquals(ctxWrong, slhdsa.ni_initSign(bad, keyRef, NO_CONTEXT, 0, PURE, HEDGED, RND));
                Assertions.assertEquals(ctxWrong, slhdsa.ni_initVerify(bad, keyRef, NO_CONTEXT, 0, PURE, HEDGED));
                Assertions.assertEquals(ctxWrong, slhdsa.ni_update(bad, new byte[8], 0, 8));
                Assertions.assertEquals(ctxWrong, slhdsa.ni_sign(bad, null, 0, RND));
                Assertions.assertEquals(ctxWrong, slhdsa.ni_sign(bad, new byte[64], 0, RND));
                Assertions.assertEquals(ctxWrong, slhdsa.ni_verify(bad, new byte[64], 64));
            }

            Assertions.assertEquals(specWrong, slhdsa.ni_getPublicKey(ref, null));
            Assertions.assertEquals(specWrong, slhdsa.ni_getPublicKey(ref, new byte[32]));
            Assertions.assertEquals(specWrong, slhdsa.ni_getPrivateKey(ref, null));
            Assertions.assertEquals(specWrong, slhdsa.ni_getPrivateKey(ref, new byte[64]));
            Assertions.assertEquals(specWrong, slhdsa.ni_decode_publicKey(ref, KT_128F, new byte[32], 0, 32));
            Assertions.assertEquals(specWrong, slhdsa.ni_decode_privateKey(ref, KT_128F, new byte[64], 0, 64));
            Assertions.assertEquals(specWrong, slhdsa.ni_initSign(ref, ref, NO_CONTEXT, 0, PURE, HEDGED, RND));
            Assertions.assertEquals(specWrong, slhdsa.ni_initVerify(ref, ref, NO_CONTEXT, 0, PURE, HEDGED));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> slhdsa.update(mdRef, new byte[8], 0, 8));
            Assertions.assertEquals("handle is not an SLH-DSA signer context", e.getMessage());
            e = Assertions.assertThrows(IllegalArgumentException.class, () -> slhdsa.getPublicKey(ref, null));
            Assertions.assertEquals("handle is not a key spec", e.getMessage());

            // A dispose of the wrong kind frees nothing: each handle still answers as its own kind afterwards.
            slhdsa.disposeSigner(keyRef);
            slhdsa.disposeSigner(rsaSigRef);
            slhdsa.disposeSigner(mdRef);
            slhdsa.disposeSigner(mldsaRef);
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
            Assertions.assertEquals(code(ErrorCode.JO_INCORRECT_KEY_TYPE),
                    slhdsa.ni_initVerify(ref, keyRef, NO_CONTEXT, 0, PURE, HEDGED));
            Assertions.assertEquals(code(ErrorCode.JO_MLDSA_CTX_WRONG_KIND),
                    mldsa.ni_update(ref, new byte[8], 0, 8));
        }
        finally
        {
            slhdsa.disposeSigner(ref);
            mldsa.disposeSigner(mldsaRef);
            md.dispose(mdRef);
            rsa.disposeSigner(rsaSigRef);
            spec.dispose(keyRef);
        }
    }

    /** Each entry checks the context, then the key, then the RandSource, then the arrays. */
    public static void theContextThenTheKeyThenTheRandSourceAreChecked(SLHDSAServiceNI slhdsa, SpecNI spec)
    {
        int ctxWrong = code(ErrorCode.JO_SLHDSA_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        int noRand = code(ErrorCode.JO_RAND_NO_RAND_UP_CALL);
        long keyRef = spec.allocate();
        long ref = slhdsa.allocateSigner();
        try
        {
            Assertions.assertEquals(ctxWrong, slhdsa.ni_initSign(keyRef, ref, null, 5, PURE, HEDGED, null));
            Assertions.assertEquals(specWrong, slhdsa.ni_initSign(ref, ref, null, 5, PURE, HEDGED, null));
            Assertions.assertEquals(code(ErrorCode.JO_KEY_SPEC_IS_NULL),
                    slhdsa.ni_initSign(ref, 0, null, 5, PURE, HEDGED, null));
            Assertions.assertEquals(noRand, slhdsa.ni_initSign(ref, keyRef, null, 5, PURE, HEDGED, null));
            Assertions.assertEquals(code(ErrorCode.JO_CONTEXT_BYTES_NULL),
                    slhdsa.ni_initSign(ref, keyRef, null, 5, PURE, HEDGED, RND));
            Assertions.assertEquals(ctxWrong, slhdsa.ni_initVerify(keyRef, ref, null, 5, PURE, HEDGED));
            Assertions.assertEquals(specWrong, slhdsa.ni_initVerify(ref, ref, null, 5, PURE, HEDGED));
            Assertions.assertEquals(code(ErrorCode.JO_CONTEXT_BYTES_NULL),
                    slhdsa.ni_initVerify(ref, keyRef, null, 5, PURE, HEDGED));
            Assertions.assertEquals(ctxWrong, slhdsa.ni_sign(keyRef, null, 0, null));
            Assertions.assertEquals(noRand, slhdsa.ni_sign(ref, null, 0, null));
            Assertions.assertEquals(ctxWrong, slhdsa.ni_update(keyRef, null, 0, 0));
            Assertions.assertEquals(code(ErrorCode.JO_INPUT_IS_NULL), slhdsa.ni_update(ref, null, 0, 0));
            Assertions.assertEquals(ctxWrong, slhdsa.ni_verify(keyRef, null, 0));
            Assertions.assertEquals(code(ErrorCode.JO_SIG_IS_NULL), slhdsa.ni_verify(ref, null, 0));
            Assertions.assertEquals(specWrong, slhdsa.ni_decode_publicKey(ref, KT_128F, null, 0, 0));
            Assertions.assertEquals(code(ErrorCode.JO_INPUT_IS_NULL),
                    slhdsa.ni_decode_publicKey(keyRef, KT_128F, null, 0, 0));
            Assertions.assertEquals(code(ErrorCode.JO_INPUT_IS_NULL),
                    slhdsa.ni_decode_privateKey(keyRef, KT_128F, null, 0, 0));
        }
        finally
        {
            slhdsa.disposeSigner(ref);
            spec.dispose(keyRef);
        }
    }

    /**
     * A key holding only its public half opens no signing session, under either message encoding, and the refusal
     * comes before anything is allocated; the full key still signs.
     */
    public static void aPublicOnlyKeyOpensNoSigningSession(SLHDSAServiceNI slhdsa, SpecNI spec)
    {
        long pairRef = slhdsa.generateKeyPair(KT_128F, RND);
        long pubRef = spec.allocate();
        long ref = slhdsa.allocateSigner();
        try
        {
            byte[] pub = new byte[slhdsa.getPublicKey(pairRef, null)];
            slhdsa.getPublicKey(pairRef, pub);
            Assertions.assertEquals(0, slhdsa.ni_decode_publicKey(pubRef, KT_128F, pub, 0, pub.length));

            int noPrivate = code(ErrorCode.JO_KEY_HAS_NO_PRIVATE_HALF);
            for (int encoding : new int[]{PURE, NO_ENCODING})
            {
                Assertions.assertEquals(noPrivate,
                        slhdsa.ni_initSign(ref, pubRef, NO_CONTEXT, 0, encoding, HEDGED, RND), "encoding " + encoding);
                Assertions.assertEquals(code(ErrorCode.JO_NOT_INITIALIZED), slhdsa.ni_sign(ref, null, 0, RND));
            }
            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> slhdsa.initSign(ref, pubRef, NO_CONTEXT, 0, PURE, HEDGED, RND));
            Assertions.assertEquals("key has no private half", e.getMessage());

            Assertions.assertEquals(0, slhdsa.ni_initSign(ref, pairRef, NO_CONTEXT, 0, PURE, HEDGED, RND));
            Assertions.assertEquals(0, slhdsa.ni_initVerify(ref, pubRef, NO_CONTEXT, 0, PURE, HEDGED));
        }
        finally
        {
            slhdsa.disposeSigner(ref);
            spec.dispose(pubRef);
            spec.dispose(pairRef);
        }
    }

    /** The private decoder takes 4n bytes only; the 3n seed form is refused typed at the length check. */
    public static void aPrivateKeyIsFourNBytesOnly(SLHDSAServiceNI slhdsa, SpecNI spec)
    {
        long pairRef = slhdsa.generateKeyPair(KT_128F, RND);
        long ref = spec.allocate();
        try
        {
            byte[] priv = new byte[slhdsa.getPrivateKey(pairRef, null)];
            Assertions.assertEquals(4 * N_128, priv.length);
            slhdsa.getPrivateKey(pairRef, priv);
            Assertions.assertEquals(0, slhdsa.ni_decode_privateKey(ref, KT_128F, priv, 0, priv.length));
            int lenWrong = code(ErrorCode.JO_ENCODED_PRIVATE_KEY_LEN);
            for (int len : new int[]{3 * N_128, 4 * N_128 - 1, 4 * N_128 + 1, 1})
            {
                byte[] bytes = new byte[len];
                RANDOM.nextBytes(bytes);
                Assertions.assertEquals(lenWrong, slhdsa.ni_decode_privateKey(ref, KT_128F, bytes, 0, len),
                        "length " + len);
            }
        }
        finally
        {
            spec.dispose(ref);
            spec.dispose(pairRef);
        }
    }

    /**
     * A written signature and a verification each consume the session: the next call answers "not initialised"
     * instead of signing an empty message or verifying against one. A length query consumes nothing.
     */
    public static void signAndVerifyConsumeTheSession(SLHDSAServiceNI slhdsa, SpecNI spec)
    {
        long pairRef = slhdsa.generateKeyPair(KT_128F, RND);
        long ref = slhdsa.allocateSigner();
        try
        {
            int notInitialised = code(ErrorCode.JO_NOT_INITIALIZED);
            byte[] msg = new byte[1 + RANDOM.nextInt(64)];
            RANDOM.nextBytes(msg);
            Assertions.assertEquals(0, slhdsa.ni_initSign(ref, pairRef, NO_CONTEXT, 0, PURE, HEDGED, RND));
            Assertions.assertEquals(0, slhdsa.ni_update(ref, msg, 0, msg.length));
            int len = slhdsa.ni_sign(ref, null, 0, RND);
            Assertions.assertEquals(len, slhdsa.ni_sign(ref, null, 0, RND));
            byte[] sig = new byte[len];
            Assertions.assertEquals(len, slhdsa.ni_sign(ref, sig, 0, RND));
            Assertions.assertEquals(notInitialised, slhdsa.ni_sign(ref, new byte[len], 0, RND));
            Assertions.assertEquals(notInitialised, slhdsa.ni_update(ref, msg, 0, msg.length));

            Assertions.assertEquals(0, slhdsa.ni_initVerify(ref, pairRef, NO_CONTEXT, 0, PURE, HEDGED));
            Assertions.assertEquals(0, slhdsa.ni_update(ref, msg, 0, msg.length));
            Assertions.assertEquals(0, slhdsa.ni_verify(ref, sig, sig.length));
            Assertions.assertEquals(notInitialised, slhdsa.ni_verify(ref, sig, sig.length));
        }
        finally
        {
            slhdsa.disposeSigner(ref);
            spec.dispose(pairRef);
        }
    }
}
