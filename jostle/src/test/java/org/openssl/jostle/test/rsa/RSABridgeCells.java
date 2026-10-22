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
import org.openssl.jostle.jcajce.provider.ErrorCode;
import org.openssl.jostle.jcajce.provider.md.MDServiceNI;
import org.openssl.jostle.jcajce.provider.rsa.RSAServiceNI;
import org.openssl.jostle.jcajce.spec.SpecNI;
import org.openssl.jostle.rand.RandSource;
import org.openssl.jostle.test.TestUtil;

/**
 * RSA bridge cells shared by the base and FIPS limit tests: each takes the NI set under test, so one body pins
 * both interface libraries on whichever bridge the leg loads.
 */
public final class RSABridgeCells
{
    private static final RandSource RND = TestUtil.RNDSrc;
    private static final byte[] E_65537 = {0x01, 0x00, 0x01};
    private static final int BITS = 2048;
    private static final String DIGEST = "SHA256";
    private static final int PKCS1 = RSAServiceNI.PADDING_PKCS1;
    private static final int PSS = RSAServiceNI.PADDING_PSS;
    private static final int RAW = RSAServiceNI.PADDING_PKCS1_NONE;

    private RSABridgeCells()
    {
    }

    private static int code(ErrorCode c)
    {
        return c.getCode();
    }

    /**
     * A key spec or a digest context as the signer, and a signer as the key spec, are each refused with a typed
     * code at every entry that takes the handle, before anything past its kind is read.
     */
    public static void wrongKindHandlesAreRefused(RSAServiceNI rsa, SpecNI spec, MDServiceNI md)
    {
        int ctxWrong = code(ErrorCode.JO_RSA_CTX_WRONG_KIND);
        int specWrong = code(ErrorCode.JO_KEY_SPEC_WRONG_KIND);
        long keyRef = rsa.generateKeyPair(BITS, E_65537, RND);
        long sigRef = rsa.allocateSigner();
        long mdRef = md.allocateDigest(DIGEST, 0);
        try
        {
            for (long bad : new long[]{keyRef, mdRef})
            {
                Assertions.assertEquals(ctxWrong, rsa.ni_initSign(bad, keyRef, DIGEST, PKCS1, null, 0, RND));
                Assertions.assertEquals(ctxWrong, rsa.ni_initVerify(bad, keyRef, DIGEST, PKCS1, null, 0));
                Assertions.assertEquals(ctxWrong, rsa.ni_update(bad, new byte[8], 0, 8));
                Assertions.assertEquals(ctxWrong, rsa.ni_sign(bad, null, 0, RND));
                Assertions.assertEquals(ctxWrong, rsa.ni_sign(bad, new byte[256], 0, RND));
                Assertions.assertEquals(ctxWrong, rsa.ni_verify(bad, new byte[256], 256));
            }

            Assertions.assertEquals(specWrong, rsa.ni_initSign(sigRef, sigRef, DIGEST, PKCS1, null, 0, RND));
            Assertions.assertEquals(specWrong, rsa.ni_initVerify(sigRef, sigRef, DIGEST, PKCS1, null, 0));
            Assertions.assertEquals(specWrong, rsa.ni_initSign(sigRef, mdRef, DIGEST, PKCS1, null, 0, RND));
            Assertions.assertEquals(specWrong, rsa.ni_decodePublicComponents(sigRef, new byte[]{1}, E_65537));
            Assertions.assertEquals(specWrong, rsa.ni_decodePrivateComponents(sigRef, new byte[]{1}, E_65537,
                    new byte[]{1}));
            Assertions.assertEquals(specWrong, rsa.ni_decodePrivateComponentsCrt(sigRef, new byte[]{1}, E_65537,
                    new byte[]{1}, new byte[]{1}, new byte[]{1}, new byte[]{1}, new byte[]{1}, new byte[]{1}));
            Assertions.assertEquals(specWrong, rsa.ni_getComponent(sigRef, RSAServiceNI.COMP_MODULUS, null));
            Assertions.assertEquals(specWrong, rsa.ni_getComponent(mdRef, RSAServiceNI.COMP_MODULUS, new byte[8]));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> rsa.update(keyRef, new byte[8], 0, 8));
            Assertions.assertEquals("handle is not an RSA signer context", e.getMessage());
            e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> rsa.getComponent(sigRef, RSAServiceNI.COMP_MODULUS, null));
            Assertions.assertEquals("handle is not a key spec", e.getMessage());

            // A dispose of the wrong kind frees nothing: the handles still work afterwards.
            rsa.disposeSigner(keyRef);
            rsa.disposeSigner(mdRef);
            Assertions.assertEquals(0, rsa.ni_initSign(sigRef, keyRef, DIGEST, PKCS1, null, 0, RND));
            Assertions.assertEquals(256, rsa.ni_sign(sigRef, null, 0, RND));
            Assertions.assertEquals(32, md.ni_getDigestOutputLen(mdRef));
        }
        finally
        {
            md.dispose(mdRef);
            rsa.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /**
     * An empty digest or MGF1 name, one with an embedded NUL, and one the library cannot fetch are refused with
     * the same code on both bridges; a JDK spelling is fetched, and BouncyCastle's truncated-SHA-512 spelling is
     * one OpenSSL does not know (the SPI canonicalises it before the NI).
     */
    public static void unusableDigestNamesAreRefused(RSAServiceNI rsa, SpecNI spec)
    {
        int refused = code(ErrorCode.JO_RSA_DIGEST_NOT_SUPPORTED);
        long keyRef = rsa.generateKeyPair(BITS, E_65537, RND);
        long sigRef = rsa.allocateSigner();
        try
        {
            for (String bad : new String[]{"SHA256\u0000junk", "", "NOPE", "SHA512(256)"})
            {
                for (int padding : new int[]{PKCS1, PSS})
                {
                    Assertions.assertEquals(refused, rsa.ni_initSign(sigRef, keyRef, bad, padding, null, -1, RND),
                            bad);
                    Assertions.assertEquals(refused, rsa.ni_initVerify(sigRef, keyRef, bad, padding, null, -1),
                            bad);
                }
                Assertions.assertEquals(refused, rsa.ni_initSign(sigRef, keyRef, DIGEST, PSS, bad, -1, RND), bad);
                Assertions.assertEquals(refused, rsa.ni_initVerify(sigRef, keyRef, DIGEST, PSS, bad, -1), bad);
            }
            Assertions.assertEquals(code(ErrorCode.JO_NAME_IS_NULL),
                    rsa.ni_initSign(sigRef, keyRef, null, PSS, DIGEST, -1, RND));
            Assertions.assertEquals(code(ErrorCode.JO_NAME_IS_NULL),
                    rsa.ni_initVerify(sigRef, keyRef, null, PSS, DIGEST, -1));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> rsa.initVerify(sigRef, keyRef, "NOPE", PKCS1, null, 0));
            Assertions.assertEquals("RSA digest is not supported", e.getMessage());

            for (String good : new String[]{"SHA-256", "SHA2-256", "SHA-512/256", DIGEST})
            {
                Assertions.assertEquals(0, rsa.ni_initSign(sigRef, keyRef, good, PSS, good, -1, RND), good);
                Assertions.assertEquals(0, rsa.ni_initVerify(sigRef, keyRef, good, PSS, good, -1), good);
            }
            // A null MGF1 name falls back to the signing digest.
            Assertions.assertEquals(0, rsa.ni_initSign(sigRef, keyRef, DIGEST, PSS, null, -1, RND));
        }
        finally
        {
            rsa.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /**
     * NoneWithRSA buffers at most the key's PKCS#1 v1.5 bound (modulus bytes - 11) and refuses the update that
     * would pass it, on both sign and verify sessions; the input that fits still signs.
     */
    public static void rawInputIsBoundedByTheKey(RSAServiceNI rsa, SpecNI spec)
    {
        int tooLong = code(ErrorCode.JO_RSA_RAW_INPUT_TOO_LONG);
        int bound = BITS / 8 - 11;
        long keyRef = rsa.generateKeyPair(BITS, E_65537, RND);
        long sigRef = rsa.allocateSigner();
        try
        {
            rsa.initSign(sigRef, keyRef, "NONE", RAW, null, 0, RND);
            Assertions.assertEquals(tooLong, rsa.ni_update(sigRef, new byte[bound + 1], 0, bound + 1));
            Assertions.assertEquals(0, rsa.ni_update(sigRef, new byte[bound - 1], 0, bound - 1));
            Assertions.assertEquals(0, rsa.ni_update(sigRef, new byte[1], 0, 1));
            Assertions.assertEquals(tooLong, rsa.ni_update(sigRef, new byte[1], 0, 1));
            Assertions.assertEquals(0, rsa.ni_update(sigRef, new byte[1], 0, 0));
            Assertions.assertEquals(256, rsa.ni_sign(sigRef, new byte[256], 0, RND));

            rsa.initVerify(sigRef, keyRef, "NONE", RAW, null, 0);
            Assertions.assertEquals(tooLong, rsa.ni_update(sigRef, new byte[bound + 1], 0, bound + 1));
            Assertions.assertEquals(tooLong, rsa.ni_update(sigRef, new byte[Integer.MAX_VALUE / 1024], 0,
                    Integer.MAX_VALUE / 1024));

            IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                    () -> rsa.update(sigRef, new byte[bound + 1], 0, bound + 1));
            Assertions.assertEquals("input is longer than the key can sign with PKCS#1 v1.5 padding", e.getMessage());
        }
        finally
        {
            rsa.disposeSigner(sigRef);
            spec.dispose(keyRef);
        }
    }

    /** A key size of zero or below is refused at both bridges before the random source is read. */
    public static void nonPositiveBitsAreRefused(RSAServiceNI rsa)
    {
        int refused = code(ErrorCode.JO_RSA_BITS_OUT_OF_RANGE);
        for (int bits : new int[]{0, -1, Integer.MIN_VALUE})
        {
            int[] err = new int[1];
            Assertions.assertEquals(0L, rsa.ni_generateKeyPair(bits, E_65537, err, RND), "bits " + bits);
            Assertions.assertEquals(refused, err[0], "bits " + bits);
            err[0] = 0;
            Assertions.assertEquals(0L, rsa.ni_generateKeyPair(bits, E_65537, err, null), "bits " + bits);
            Assertions.assertEquals(refused, err[0], "bits " + bits);
        }
        IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
                () -> rsa.generateKeyPair(0, E_65537, RND));
        Assertions.assertEquals("RSA key size out of range", e.getMessage());
    }

    /**
     * The library's generation floor is asked of it: one bit below is refused by the library itself, so the
     * answer is the floor and not a guess.
     */
    public static void minModulusBitsIsTheLibrarysFloor(RSAServiceNI rsa)
    {
        int floor = rsa.minModulusBits();
        Assertions.assertTrue(floor > 1, "floor " + floor);
        int[] err = new int[1];
        Assertions.assertEquals(0L, rsa.ni_generateKeyPair(floor - 1, E_65537, err, RND));
        Assertions.assertEquals(code(ErrorCode.JO_OPENSSL_ERROR), err[0]);
    }
}
